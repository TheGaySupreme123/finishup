"""The recorded four-event publish batch must project to a complete success.

2026-07-27 Codex dogfood, ``req_7b8c9d0e-1f2a-4b34-8567-8d9e0f1a2b34``: a durable four-event
publish (action/result/evidence/claim) surfaced as ``response_projection_failed`` after the
append had committed. The internal result materialized a phantom ``"summary": null`` leaf on
every accepted event. While the leaf's category was blocked for the agent context it was
replaced by an omission marker, so the earlier single ``plan_published`` publish (whose
``task_description`` summary is blocked by the shipped default) projected cleanly. The defect
fired as soon as a batch contained an event whose summary category the shipped default policy
*includes* for the agent context (``claim_recorded`` → ``finding_summary``): the null survived
disclosure and the closed wire model rejected it (``optional_field_must_not_be_null`` — the
frozen schema never admits an explicit null summary, only text, an omission, or absence).

An unpopulated summary is now simply absent from the internal body, so projection no longer
depends on the policy's disposition of a leaf that was never content. These cases replay the
exact recorded batch through the real privacy coordinator seeded with the shipped default's
disclosure disposition — the same classification, disclosure decision, and closed-model validation the daemon
runs for an MCP bridge client — and pin the complete response, including the stored-response
replay the dogfood never reached.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import cast

import pytest

import yoetz.service.ready_composition as ready_composition
from builders.ledger_adapters import MemoryObjects, ownership_fence
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
from yoetz.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from yoetz.application.egress import PrivacyCoordinator
from yoetz.application.publish_work import PublishWorkInternalResult
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
    LocalDisclosureSink,
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
from yoetz.ports.objects import ObjectStorePort
from yoetz.ports.publish_response_catalog import PublishResponseCatalogPort
from yoetz.ports.runtime import BundleRuntimePort, RouteCommand, TaskRuntime
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.models import (
    DataCategory,
    FrontierModel,
    PublishWorkRequest,
    public_model_to_wire,
)

# The exact bootstrap default the ready composition seeds: the ADR-009 agent-context allowlist
# (bounded structural metadata, declared file type, finding summary, obligation text). Reaching
# for the private builder on purpose: the regression only means something if the policy under
# test is identical in disposition to the one the daemon seeds, including the ``finding_summary``
# inclusion that made the recorded batch crash.
_denied_policy = cast(
    "Callable[..., PrivacyPolicy]",
    getattr(ready_composition, "_denied_policy"),
)

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "7" * 64
_WORKSPACE = "hmac-sha256:" + "8" * 64
_INSTALLATION = protocol_id("ins_", 1204)
_NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)


class _IdleImporter:
    """Provide a stable idle importer status for projection tests."""

    async def status(self, session: str) -> ImportStatusSnapshot:
        """Return an empty importer snapshot for the requested session."""

        from yoetz.domain.values import session_id

        return ImportStatusSnapshot(session_id(session), 0, 0, (), ())


_CAPABILITIES = frozenset(
    {
        RuntimeCapability.WRITE,
        RuntimeCapability.STRUCTURAL_READ,
        RuntimeCapability.PAYLOAD_READ,
    }
)


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


def _shipped_default_policy() -> PrivacyPolicy:
    """Build the shipped default policy at stable test identities."""

    return _denied_policy(
        installation_id=_INSTALLATION,
        policy_id=protocol_id("pvy_", 1201),
        policy_digest=_DIGEST,
        created_at=_NOW,
    )


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
        schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.0.0"),),
        resource_manifest_digest=_DIGEST,
    )


def _scope(_: ControlProjectionBinding, source: Mapping[str, JsonValue]) -> AuthorizationScope:
    """Bind disclosure to the projected result's task identity."""

    return AuthorizationScope(
        AuthorizationScopeKind.TASK,
        _INSTALLATION,
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
    """Fail if the local projection unexpectedly invokes AI-powered evaluation."""

    del frozen, findings, runtime, lineage_evaluation
    raise AssertionError("semantic_evaluator_called_in_deterministic_mode")


def _request_base(request_id: str) -> dict[str, JsonValue]:
    """Build the common recorded MCP request envelope."""

    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
        "actor": {
            "actor_id": "codex-grok-easy-linking",
            "actor_type": "logical_agent",
            "display_name": "Codex",
        },
        "client": {
            "kind": "cooperative_agent",
            "version": "1.0",
            "integration": "cooperative_mcp",
        },
    }


def _frontier(value: Frontier | FrontierModel) -> JsonValue:
    """Normalize domain and wire frontiers to JSON."""

    if isinstance(value, Frontier):
        return cast(JsonValue, dict(value.as_wire().items()))
    return cast(JsonValue, value.model_dump(mode="json"))


async def _application() -> tuple[Application, PrivacyPolicy]:
    """A ready application whose disclosure boundary is the real coordinator and default policy."""

    start_app, start_runtime, clock, catalog = start_composition()
    ids = start_runtime.ids
    privacy_state = MemoryPrivacyCatalogState()
    policies = MemoryPrivacyPolicyStore(privacy_state, clock)
    policy = _shipped_default_policy()
    await policies.seed_if_absent(policy)
    audit = MemoryPrivacyAudit(
        privacy_state, cast(ObjectStorePort, MemoryObjects(ids)), StartTestLookup(), clock
    )
    coordinator = PrivacyCoordinator(
        policies,
        LocalPrivacyEnforcer(),
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
        verification_policy=VerificationPolicy(semantic="disabled", max_findings=3),
        privacy=coordinator,
        status_cursor_key=b"publish-summary-projection-cursor",
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
    return app, policy


async def _project(
    app: Application,
    request_body: Mapping[str, JsonValue],
    internal: PublishWorkInternalResult,
    seed: int,
) -> Mapping[str, JsonValue]:
    """Run the daemon's exact post-commit projection sequence for an MCP bridge client."""

    context = ClientProjectionContext(
        ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
    )
    projected = await app.project_result_for_client(
        context, await _binding(app, request_body, internal, seed), internal
    )
    return public_model_to_wire(projected)


# Payloads retained from a 2026-07-27 local interoperability run. Only the installation-bound
# identities (request/session/writer/frontier) are supplied by the replay.
_PLAN_DRAFT: Mapping[str, JsonValue] = {
    "event_id": "evt_4a1b2c3d-5e6f-4a78-9b01-2c3d4e5f6a78",
    "schema": {"name": "plan_published", "version": "1.0.0"},
    "occurred_at": "2026-07-27T00:00:00.000Z",
    "causal_parents": [],
    "payload": {
        "plan_version": 1,
        "summary": (
            "Trace reviewed provider setup and exact Chat Completions dispatch; add only the "
            "Grok/xAI preset and operator shortcuts that preserve credential, privacy, "
            "request-byte, provenance, and receipt boundaries; verify locally and report live "
            "interoperability honestly."
        ),
        "obligation_refs": [],
    },
    "artifact_refs": [],
    "evidence_refs": [],
}

_RECORDED_DRAFTS: tuple[Mapping[str, JsonValue], ...] = (
    {
        "event_id": "evt_5b2c3d4e-6f7a-4b89-8c12-3d4e5f6a7b89",
        "schema": {"name": "action_recorded", "version": "1.0.0"},
        "occurred_at": "2026-07-27T16:55:00.000Z",
        "causal_parents": ["evt_4a1b2c3d-5e6f-4a78-9b01-2c3d4e5f6a78"],
        "payload": {
            "action_id": "act_5b2c3d4e-6f7a-4b89-8c12-3d4e5f6a7b89",
            "action_kind": "edit",
            "description": (
                "Added the exact xAI/Grok preset, Chat Completions factory profile, operator "
                "aliases, focused tests, and authority documentation."
            ),
        },
        "artifact_refs": [],
        "evidence_refs": [],
    },
    {
        "event_id": "evt_6c3d4e5f-7a8b-4c90-8d23-4e5f6a7b8c90",
        "schema": {"name": "result_recorded", "version": "1.0.0"},
        "occurred_at": "2026-07-27T16:56:00.000Z",
        "causal_parents": ["evt_5b2c3d4e-6f7a-4b89-8c12-3d4e5f6a7b89"],
        "payload": {
            "result_id": "res_6c3d4e5f-7a8b-4c90-8d23-4e5f6a7b8c90",
            "action_id": "act_5b2c3d4e-6f7a-4b89-8c12-3d4e5f6a7b89",
            "outcome": "success",
            "summary": (
                "Focused provider, request-shape, and CLI tests passed; temporary config "
                "exercise resolved one factory and retained unknown data-use posture."
            ),
        },
        "artifact_refs": [],
        "evidence_refs": [],
    },
    {
        "event_id": "evt_7d4e5f6a-8b9c-4d01-8e34-5f6a7b8c9d01",
        "schema": {"name": "evidence_recorded", "version": "1.0.0"},
        "occurred_at": "2026-07-27T16:57:00.000Z",
        "causal_parents": ["evt_6c3d4e5f-7a8b-4c90-8d23-4e5f6a7b8c90"],
        "payload": {
            "evidence_id": "evd_7d4e5f6a-8b9c-4d01-8e34-5f6a7b8c9d01",
            "evidence_kind": "test_result",
            "strength": "metadata_only",
            "observed_at": "2026-07-27T16:57:00.000Z",
            "reference": "focused pytest slice and temporary nonsecret binding/factory exercise",
        },
        "artifact_refs": [],
        "evidence_refs": [],
    },
    {
        "event_id": "evt_8e5f6a7b-9c0d-4e12-8f45-6a7b8c9d0e12",
        "schema": {"name": "claim_recorded", "version": "1.0.0"},
        "occurred_at": "2026-07-27T16:58:00.000Z",
        "causal_parents": ["evt_7d4e5f6a-8b9c-4d01-8e34-5f6a7b8c9d01"],
        "payload": {
            "claim_id": "clm_8e5f6a7b-9c0d-4e12-8f45-6a7b8c9d0e12",
            "claim_kind": "completion",
            "statement": (
                "The local Grok/xAI easy-linking path is implemented through the exact provider "
                "preset and existing Chat Completions dispatch boundary, with live "
                "interoperability still unverified and unknown provider data-use posture "
                "preserved."
            ),
            "supporting_refs": [
                "evd_7d4e5f6a-8b9c-4d01-8e34-5f6a7b8c9d01",
                "res_6c3d4e5f-7a8b-4c90-8d23-4e5f6a7b8c90",
            ],
        },
        "artifact_refs": [],
        "evidence_refs": [
            "evd_7d4e5f6a-8b9c-4d01-8e34-5f6a7b8c9d01",
            "res_6c3d4e5f-7a8b-4c90-8d23-4e5f6a7b8c90",
        ],
    },
)


async def _publish_recorded_session(
    app: Application,
) -> tuple[PublishWorkInternalResult, dict[str, JsonValue]]:
    """Replay the recorded session: the plan publish, then the four-event batch."""

    started = await app.start(start_request(1210, title="Implement Grok/xAI easy linking"))
    plan_wire = {
        **_request_base("req_3f8a0e21-6b4c-4d9f-a127-5e6c7b8d9a01"),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(started.frontier),
        "event_drafts": [_PLAN_DRAFT],
    }
    plan = await app.publish_work(PublishWorkRequest.model_validate(plan_wire))
    assert type(plan) is PublishWorkInternalResult

    batch_wire: dict[str, JsonValue] = {
        **_request_base("req_7b8c9d0e-1f2a-4b34-8567-8d9e0f1a2b34"),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(plan.result_frontier),
        "event_drafts": list(_RECORDED_DRAFTS),
    }
    batch = await app.publish_work(PublishWorkRequest.model_validate(batch_wire))
    assert type(batch) is PublishWorkInternalResult
    return batch, batch_wire


async def test_recorded_four_event_batch_projects_to_a_complete_success() -> None:
    """Project the exact failed dogfood batch as a complete success."""

    app, policy = await _application()
    # The pre-fix crash condition: the shipped default really does include the claim's summary
    # category for the agent context, so the phantom null leaf survived disclosure.
    assert DataCategory.FINDING_SUMMARY in policy.agent_context_categories
    assert DataCategory.COMMAND_METADATA not in policy.agent_context_categories
    assert DataCategory.EVIDENCE_EXCERPT not in policy.agent_context_categories

    batch, batch_wire = await _publish_recorded_session(app)
    projected = await _project(app, batch_wire, batch, 1220)

    assert projected["ok"] is True
    assert projected["outcome"] == "accepted"
    assert "response_completeness" not in projected
    events = cast(list[Mapping[str, JsonValue]], projected["accepted_events"])
    assert [event["event_id"] for event in events] == [
        "evt_5b2c3d4e-6f7a-4b89-8c12-3d4e5f6a7b89",
        "evt_6c3d4e5f-7a8b-4c90-8d23-4e5f6a7b8c90",
        "evt_7d4e5f6a-8b9c-4d01-8e34-5f6a7b8c9d01",
        "evt_8e5f6a7b-9c0d-4e12-8f45-6a7b8c9d0e12",
    ]
    # No summary was ever populated, so the honest shape carries no summary at all — never an
    # explicit null and never an omission marker for content that does not exist.
    for event in events:
        assert "summary" not in event
    projection = cast(Mapping[str, JsonValue], projected["privacy_projection"])
    assert projection["sink"] == "agent_context"
    assert projection["included_categories"] == []
    assert projection["blocked_categories"] == []
    assert projection["omitted_pointers"] == []


async def test_recorded_batch_stored_response_replays_the_complete_success() -> None:
    """Persist and replay the exact projected response without re-projecting it."""

    app, _policy = await _application()
    batch, batch_wire = await _publish_recorded_session(app)

    # The daemon's publish replay path: miss on first completion, hit on the byte-identical retry.
    first = await app.load_publish_response(batch, LocalDisclosureSink.AGENT_CONTEXT)
    assert first is None
    projected = await app.project_result_for_client(
        ClientProjectionContext(
            ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
        ),
        await _binding(app, batch_wire, batch, 1240),
        batch,
    )
    persisted = await app.store_publish_response(
        batch, LocalDisclosureSink.AGENT_CONTEXT, projected
    )

    replayed = await app.publish_work(PublishWorkRequest.model_validate(batch_wire))
    assert type(replayed) is PublishWorkInternalResult
    assert replayed.outcome == "replayed"
    loaded = await app.load_publish_response(replayed, LocalDisclosureSink.AGENT_CONTEXT)
    assert loaded is not None
    assert public_model_to_wire(loaded) == public_model_to_wire(persisted)
    wire = public_model_to_wire(loaded)
    assert wire["ok"] is True
    assert len(cast(list[object], wire["accepted_events"])) == 4


async def _binding(
    app: Application,
    request_body: Mapping[str, JsonValue],
    internal: PublishWorkInternalResult,
    seed: int,
) -> ControlProjectionBinding:
    """Build the daemon-equivalent projection binding for a recorded publish."""

    facts = await app.projection_binding_facts(ControlMethod.PUBLISH_WORK, request_body, internal)
    rpc_id = protocol_id("rpc_", seed)
    service_instance_id = protocol_id("svc_", seed + 1)
    return ControlProjectionBinding(
        rpc_id,
        ControlMethod.PUBLISH_WORK,
        service_instance_id,
        1,
        facts.original_request_id,
        facts.route_identity_digest,
        canonical_encode(
            {
                "rpc_id": rpc_id,
                "method": "publish_work",
                "service_instance_id": service_instance_id,
                "service_generation": "1",
            }
        ),
    )


async def test_fixed_summary_family_batch_projects_to_a_complete_success() -> None:
    """``assignment_recorded`` has a fixed, structural summary; its phantom null crashed too.

    The fixed-summary rule classifies the leaf ``public_structural``, so no disclosure decision
    ever rewrote it — the null reached the closed wire model on every publish of the family.
    """

    app, _policy = await _application()
    started = await app.start(start_request(1260, title="Assignment projection"))
    obligation_id = protocol_id("obl_", 1261)
    obligation_event_id = protocol_id("evt_", 1262)
    assignment_event_id = protocol_id("evt_", 1263)
    batch_wire: dict[str, JsonValue] = {
        **_request_base(protocol_id("req_", 1264)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": _frontier(started.frontier),
        "event_drafts": [
            {
                "event_id": obligation_event_id,
                "schema": {"name": "obligation_published", "version": "1.0.0"},
                "occurred_at": "2026-07-27T12:00:00.000Z",
                "causal_parents": [],
                "payload": {
                    "obligation_id": obligation_id,
                    "description": "Track the assignment projection case.",
                    "acceptance_criteria": "An assignment is recorded.",
                    "evidence_expectation": "The assignment event.",
                    "requested_items": [{"item_kind": "change", "value": "assignment"}],
                    "status": "open",
                },
                "artifact_refs": [],
                "evidence_refs": [],
            },
            {
                "event_id": assignment_event_id,
                "schema": {"name": "assignment_recorded", "version": "1.0.0"},
                "occurred_at": "2026-07-27T12:00:01.000Z",
                "causal_parents": [obligation_event_id],
                "payload": {
                    "assignee_actor_id": "codex-grok-easy-linking",
                    "obligation_ids": [obligation_id],
                    "scope_description": "Owns the assignment projection case.",
                },
                "artifact_refs": [],
                "evidence_refs": [],
            },
        ],
    }
    batch = await app.publish_work(PublishWorkRequest.model_validate(batch_wire))
    assert type(batch) is PublishWorkInternalResult
    projected = await _project(app, batch_wire, batch, 1270)

    assert projected["ok"] is True
    events = cast(list[Mapping[str, JsonValue]], projected["accepted_events"])
    assert [event["schema_name"] for event in events] == [
        "obligation_published",
        "assignment_recorded",
    ]
    for event in events:
        assert "summary" not in event
