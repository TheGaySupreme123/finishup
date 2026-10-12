"""Configured full-specification review input preflight regressions (#953).

These tests drive the ready-composition evaluator at the boundary where a configured semantic
check becomes eligible for provider admission.  The existing durable harness supplies the frozen
case and semantic job ledger; this file only adds the task-statement scenarios.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import apsw
import pytest

import integration.service.test_semantic_non_dispatch as non_dispatch
import yoetz.application.check as check_module
from builders.ledger_adapters import (
    FixedIds,
    MemoryObjects,
    append_command,
    memory_adapter,
    ownership_fence,
    sqlite_adapter,
)
from builders.multi_agent import MultiAgentService, multi_agent_service
from builders.policy_cases import BASE_COVERAGE
from builders.privacy_policies import minimal_external_policy
from builders.start_application import MemoryStartRuntime, StartTestClock, start_composition
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.adapters.memory.ledger import MemoryLedgerAdapter
from yoetz.adapters.providers.openai_responses_factory import OpenAIResponsesExternalFactory
from yoetz.adapters.repository_identity import resolve_repository_privacy_context
from yoetz.application.check import FinalSemanticEvaluation
from yoetz.application.egress import SemanticEgressSuccess
from yoetz.application.privacy_policy import (
    DecidePrivacyPolicyRequest,
    PolicyDecisionRequired,
    ProposePrivacyPolicyRequest,
    decide_privacy_policy,
    privacy_propose_policy,
)
from yoetz.application.publish_work import PublishWorkInternalResult
from yoetz.application.service import (
    ClientProjectionContext,
    ControlProjectionBinding,
    ProjectionRenderMode,
    UnprojectedControlBody,
    VerificationPolicy,
)
from yoetz.application.start import execute_start
from yoetz.config.models import YoetzConfig
from yoetz.config.write import fireworks_provider
from yoetz.domain.findings import Finding, SamplingParams, SemanticDispatchKind
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    DataCategory,
    EgressChannel,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from yoetz.domain.task_statement import RecordedTaskStatement, specification_preflight
from yoetz.domain.values import JsonObject, event_id
from yoetz.kernel.deterministic_checks import DeterministicAssessment, DeterministicCase
from yoetz.kernel.lineage import LineageEvaluation
from yoetz.ports.control import (
    ControlClientKind,
    ControlMethod,
    RepositoryPrivacyContext,
    WorkspaceLocator,
)
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.importer import ImporterPort
from yoetz.ports.keys import MacKeyPurpose
from yoetz.ports.ledger import CheckPolicyExecution, FrozenCase
from yoetz.ports.privacy import (
    EffectivePrivacyPolicy,
    HumanAuthorityCapability,
    HumanPolicyDecision,
)
from yoetz.ports.runtime import BundleRuntimePort, RouteCommand, TaskRuntime
from yoetz.ports.secret_memory import HumanAuthorizationProof, SecretPurpose
from yoetz.ports.semantic import (
    ProviderAttemptProvenance,
    SemanticJudgment,
    SemanticResultSuccess,
)
from yoetz.ports.start_catalog import StartCatalogPort, TaskRoute
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import (
    CheckRequest,
    CheckResultModel,
    PublishWorkRequest,
    SemanticReason,
    SemanticStatus,
    StartRequest,
    StatusHistoryItemV14Model,
    StatusHistoryPageModel,
    StatusRequest,
    StatusResultModel,
)
from yoetz.service.vault import provider_credential_profile_binding

pytestmark = pytest.mark.anyio

_STATEMENT_EVENT = event_id("evt_53000000-0000-4000-8000-000000000953")
_STATEMENT = "Review the requested change against the user's complete specification."
_Privacy = non_dispatch._Privacy  # pyright: ignore[reportPrivateUsage]
_PROVIDER = non_dispatch._PROVIDER  # pyright: ignore[reportPrivateUsage]
_durable_semantic_case = cast(
    Callable[..., Awaitable[tuple[FrozenCase, TaskRuntime]]],
    non_dispatch._durable_semantic_case,  # pyright: ignore[reportPrivateUsage]
)
_route_for = cast(
    Callable[[str, str], TaskRoute],
    non_dispatch._route_for,  # pyright: ignore[reportPrivateUsage]
)

type Evaluator = Callable[..., Awaitable[FinalSemanticEvaluation]]


class _SharedStartRuntime(MemoryStartRuntime):
    """START runtime whose task bundle uses the selected ledger adapter."""

    def __init__(self, clock: StartTestClock, ids: FixedIds, adapter: str) -> None:
        super().__init__(clock, ids)
        self.adapter = adapter
        self.sqlite_connections: list[apsw.Connection] = []

    async def provision_start(self, command: object) -> TaskRuntime:
        from yoetz.ports.runtime import BundleProvisionCommand

        assert type(command) is BundleProvisionCommand
        self.provisions.append(command)
        resources = self.resources.get(command.task_id)
        if resources is None:
            if self.adapter == "memory":
                from yoetz.adapters.memory.importer import MemoryImportState
                from yoetz.adapters.memory.ledger import MemoryLedgerState

                objects = MemoryObjects(self.ids)
                ledger = MemoryLedgerAdapter(
                    task_id=command.task_id,
                    ownership_fence=ownership_fence(),
                    state=MemoryLedgerState(),
                    import_state=MemoryImportState(),
                    transaction_lock=asyncio.Lock(),
                    clock=self.clock,
                    ids=self.ids,
                    objects=objects,
                )
            else:
                base = append_command()
                connection = apsw.Connection(":memory:")
                self.sqlite_connections.append(connection)
                entry = base.entries[0]
                metadata = replace(entry.payload_object.metadata, task_id=command.task_id)
                payload_object = replace(entry.payload_object, metadata=metadata)
                ledger = sqlite_adapter(
                    replace(
                        base,
                        task_id=command.task_id,
                        session_id=command.session_id,
                        writer_id=command.writer_id,
                        entries=(replace(entry, payload_object=payload_object),),
                    ),
                    db=connection,
                )
                # START drafts are stamped by the application ID source while the durable
                # adapter stamps check events. Share that source so the two families cannot mint
                # the same event ID in this in-memory composition.
                ledger._ids = self.ids  # pyright: ignore[reportPrivateUsage]
                objects = cast(MemoryObjects, ledger._objects)  # pyright: ignore[reportPrivateUsage]
            resources = (ledger, objects)
            self.resources[command.task_id] = cast(
                tuple[MemoryLedgerAdapter, MemoryObjects], resources
            )
        ledger, objects = resources
        self.owners[(command.session_id, command.writer_id)] = command.owner_generation
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
            ownership_fence(),
        )


class _CheckRuntime:
    def __init__(self, start_runtime: _SharedStartRuntime, task_id: str) -> None:
        self.start_runtime = start_runtime
        self.task_id = task_id
        self.releases = 0

    async def route(self, command: RouteCommand) -> TaskRuntime:
        ledger, objects = self.start_runtime.resources[self.task_id]
        return TaskRuntime(
            self.task_id,
            command.session_id,
            cast(str, command.writer_id),
            frozenset(
                {
                    RuntimeCapability.WRITE,
                    RuntimeCapability.PAYLOAD_READ,
                    RuntimeCapability.SEMANTIC,
                }
            ),
            ledger,
            objects,
            cast(ImporterPort, object()),
            "0.1.0",
            "0.1.0",
            "0.1",
            "1.0.0",
            ownership_fence(),
        )

    async def release(self, _runtime: TaskRuntime) -> None:
        self.releases += 1


class _PublicCheckApp:
    def __init__(self, runtime: _CheckRuntime, start_runtime: _SharedStartRuntime) -> None:
        self.runtime: BundleRuntimePort = cast(BundleRuntimePort, runtime)
        self.clock = start_runtime.clock
        self.ids = start_runtime.ids
        self.verification_policy = VerificationPolicy(semantic="required")
        self.reconcile_observation_capture = None
        self.calls = 0
        self.provider_calls = 0

    async def evaluate_semantic_check(
        self,
        frozen: FrozenCase,
        deterministic_findings: tuple[Finding, ...],
        runtime: TaskRuntime | None = None,
        lineage_evaluation: LineageEvaluation | None = None,
        require_complete_specification: bool = False,
    ) -> FinalSemanticEvaluation:
        del deterministic_findings, runtime, lineage_evaluation
        self.calls += 1
        assert require_complete_specification is True
        selection = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
        preflight = specification_preflight(
            frozen.case.task_statement,
            frozen.case.task_title,
            selection,
            required=True,
        )
        if frozen.case.task_statement is None:
            from yoetz.domain.values import review_input_continuation

            return FinalSemanticEvaluation(
                SemanticStatus.AWAITING_HUMAN,
                SemanticReason.HUMAN_APPROVAL_REQUIRED,
                continuation=review_input_continuation(request_id=frozen.lease.operation_id),
                specification_preflight=preflight,
            )
        self.provider_calls += 1
        return FinalSemanticEvaluation(
            SemanticStatus.UNAVAILABLE,
            SemanticReason.CREDENTIAL_UNAVAILABLE,
            specification_preflight=preflight,
        )


class _SuccessfulPrivacy(_Privacy):
    """Count provider dispatches and return a valid terminal review judgment."""

    async def evaluate_semantic(self, candidate: object, deadline: object) -> object:
        del deadline
        self.calls += 1
        if type(candidate) is CandidateContext:
            self.candidates.append(candidate)
        request_id = cast(str, getattr(candidate, "request_id"))
        provenance = ProviderAttemptProvenance(
            provider=_PROVIDER.provider_id,
            endpoint_profile_id=_PROVIDER.endpoint_profile_id,
            endpoint_profile_version=_PROVIDER.endpoint_profile_version,
            model=_PROVIDER.model_id,
            sdk_version="1.0.0",
            prompt_digest="sha256:" + "1" * 64,
            schema_digest="sha256:" + "2" * 64,
            policy_digest="sha256:" + "3" * 64,
            privacy_policy_digest="sha256:" + "4" * 64,
            sampling_params=SamplingParams(128),
            latency_ms=1,
            status=SemanticStatus.SUCCEEDED,
        )
        return SemanticEgressSuccess(
            request_id=request_id,
            privacy_proposal_id="ppr_53000000-0000-4000-8000-000000000953",
            authorization_id="aut_53000000-0000-4000-8000-000000000953",
            dispatch_kind=SemanticDispatchKind.EXTERNAL,
            result=SemanticResultSuccess(
                SemanticJudgment("no_material_discrepancy", ()), provenance
            ),
            case_digest="sha256:" + "5" * 64,
            privacy_receipt_id="egr_53000000-0000-4000-8000-000000000953",
            request_commitment="hmac-sha256:" + "6" * 64,
        )


def _case_with_statement(frozen: FrozenCase, statement: str | None) -> FrozenCase:
    """Attach a current statement to the same frozen request identity for replay tests."""

    case = replace(
        frozen.case,
        allowed_ids=frozenset({_STATEMENT_EVENT}) if statement is not None else frozenset(),
        coverage_by_ref={_STATEMENT_EVENT: BASE_COVERAGE} if statement is not None else {},
        task_statement=(
            None
            if statement is None
            else RecordedTaskStatement(statement, _STATEMENT_EVENT, "session_opened", 1)
        ),
        task_title=None,
    )
    return FrozenCase(case, frozen.lease)


async def _durable_case(
    *,
    privacy_type: type[_Privacy] = _Privacy,
) -> tuple[FrozenCase, TaskRuntime, _Privacy]:
    frozen, runtime = await _durable_semantic_case(memory_adapter(append_command()))
    privacy = privacy_type(
        task_id=runtime.task_id,
        profile=ReviewContextProfile.EXPANDED,
    )
    return frozen, runtime, privacy


def _evaluator(
    privacy: _Privacy,
    runtime: TaskRuntime,
) -> Evaluator:
    return cast(
        Evaluator,
        non_dispatch._evaluator(  # pyright: ignore[reportPrivateUsage]
            privacy,
            lambda: _PROVIDER,
            _route_for(runtime.task_id, runtime.session_id),
        ),
    )


@pytest.mark.anyio
async def test_missing_statement_pauses_full_spec_review_before_provider_calls() -> None:
    frozen, runtime, privacy = await _durable_case()
    provider_resolutions = 0

    def resolve_provider() -> ProviderBinding:
        nonlocal provider_resolutions
        provider_resolutions += 1
        return _PROVIDER

    evaluator = cast(
        Evaluator,
        non_dispatch._evaluator(  # pyright: ignore[reportPrivateUsage]
            privacy,
            resolve_provider,
            _route_for(runtime.task_id, runtime.session_id),
        ),
    )
    missing = _case_with_statement(frozen, None)

    result = await evaluator(
        missing,
        (),
        runtime,
        require_complete_specification=True,
    )

    assert result.status is SemanticStatus.AWAITING_HUMAN
    assert result.reason is SemanticReason.HUMAN_APPROVAL_REQUIRED
    assert result.continuation is not None
    assert result.continuation.kind == "review_input_required"
    assert result.continuation.command == ("yoetz", "publish-work", "--input", "PATH")
    assert result.continuation.request_id == frozen.lease.operation_id
    assert result.specification_preflight is not None
    assert result.specification_preflight.status == "missing"
    assert result.specification_preflight.actionable is True
    assert provider_resolutions == 0
    assert privacy.calls == 0


@pytest.mark.anyio
async def test_statement_correction_replays_same_request_and_dispatches() -> None:
    frozen, runtime, privacy = await _durable_case(privacy_type=_SuccessfulPrivacy)
    evaluator = _evaluator(privacy, runtime)

    paused = await evaluator(
        _case_with_statement(frozen, None),
        (),
        runtime,
        require_complete_specification=True,
    )
    assert paused.continuation is not None
    assert paused.continuation.request_id == frozen.lease.operation_id
    assert privacy.calls == 0

    resumed = await evaluator(
        _case_with_statement(frozen, _STATEMENT),
        (),
        runtime,
        require_complete_specification=True,
    )

    assert resumed.status is SemanticStatus.SUCCEEDED
    assert resumed.reason is SemanticReason.SEMANTIC_COMPLETED
    assert resumed.continuation is None
    assert resumed.provenance is not None
    assert privacy.calls > 0
    assert privacy.candidates[0].request_id != frozen.lease.operation_id


@pytest.mark.anyio
async def test_inherited_current_statement_is_present_in_dispatched_packet() -> None:
    frozen, runtime, privacy = await _durable_case()
    privacy.terminal_provider_result = True
    evaluator = _evaluator(privacy, runtime)

    result = await evaluator(
        _case_with_statement(frozen, _STATEMENT),
        (),
        runtime,
        require_complete_specification=True,
    )

    assert result.status is SemanticStatus.UNAVAILABLE
    assert result.continuation is None
    assert privacy.calls > 0
    candidate = privacy.candidates[0]
    statement_items = [item for item in candidate.items if item.item_id == "task-statement"]
    assert len(statement_items) == 1
    assert _STATEMENT.encode("utf-8") in statement_items[0].plaintext
    assert result.review_input_manifest is not None
    assert result.review_input_manifest.specification.status == "complete"


@pytest.mark.anyio
async def test_withheld_statement_scope_remains_explicit_and_is_not_requested() -> None:
    frozen, runtime, privacy = await _durable_case()
    privacy.terminal_provider_result = True
    store = privacy.policy_application.policy_store  # pyright: ignore[reportPrivateUsage]
    effective = store._effective  # pyright: ignore[reportPrivateUsage]
    policy = minimal_external_policy()
    withheld = replace(
        policy,
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        effective_scope=effective.policy.effective_scope,
        channel_policies=tuple(
            replace(
                channel,
                allowed_categories=tuple(
                    item
                    for item in channel.allowed_categories
                    if item is not DataCategory.TASK_DESCRIPTION
                ),
            )
            if channel.channel is EgressChannel.LLM_INFERENCE
            else channel
            for channel in policy.channel_policies
        ),
    )
    store._effective = replace(effective, policy=withheld)  # pyright: ignore[reportPrivateUsage]
    evaluator = _evaluator(privacy, runtime)

    result = await evaluator(
        _case_with_statement(frozen, _STATEMENT),
        (),
        runtime,
        require_complete_specification=True,
    )

    assert result.continuation is None
    assert privacy.calls > 0
    assert result.review_input_manifest is not None
    assert result.review_input_manifest.specification.status == "withheld"
    assert (
        "task_statement_not_authorized"
        in result.review_input_manifest.specification.omission_reasons
    )
    candidate = privacy.candidates[0]
    assert not any(item.item_id == "task-statement" for item in candidate.items)


@pytest.mark.anyio
@pytest.mark.parametrize("adapter", ("memory", "sqlite"))
async def test_durable_same_request_recovery_after_statement_event_refreshes_case(
    adapter: str,
) -> None:
    """The durable check suspension refreshes after a statement-carrying session event."""

    start_application, original_runtime, clock, catalog = start_composition()
    start_runtime = _SharedStartRuntime(clock, original_runtime.ids, adapter)
    # The START facade only needs the catalog and runtime; use the test application's immutable
    # protocol/version facts while replacing its runtime with the adapter-selected one.
    start_application.runtime = cast(BundleRuntimePort, start_runtime)  # type: ignore[misc]
    start_application.ids = start_runtime.ids
    start_application.start_catalog = cast(StartCatalogPort, catalog)
    title = "Review-input recovery task"
    common = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "actor": {"actor_id": "harness:review-input", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }
    created = await execute_start(
        start_application,
        StartRequest.model_validate(
            {
                **common,
                "request_id": "req_95300000-0000-4000-8000-000000000001",
                "mode": "create",
                "task_title": title,
                "requested_view": "compact",
            }
        ),
    )
    check_runtime = _CheckRuntime(start_runtime, created.task_id)
    check_app = _PublicCheckApp(check_runtime, start_runtime)
    request = CheckRequest.model_validate(
        {
            **common,
            "request_id": "req_95300000-0000-4000-8000-000000000002",
            "session_id": created.session_id,
            "writer_id": created.writer_id,
            "expected_frontier": created.frontier.model_dump(mode="json"),
            "mode": "semantic_required",
            "max_findings": "3",
            "policy_packs": ["work-integrity/0.3.0"],
        }
    )

    first = await check_module.execute_check_commit(check_app, request)
    assert type(first).__name__ == "CheckAwaitingHuman"
    assert getattr(first, "state") == "awaiting_input"
    assert check_app.calls == 1
    assert check_app.provider_calls == 0

    statement = "Review the complete requested behavior and verify the final implementation."
    attached = await execute_start(
        start_application,
        StartRequest.model_validate(
            {
                **common,
                "request_id": "req_95300000-0000-4000-8000-000000000003",
                "mode": "attach",
                "session_id": created.session_id,
                "task_title": title,
                "task_statement": statement,
                "requested_view": "compact",
            }
        ),
    )
    assert attached.task_id == created.task_id
    # Replay the identical check body after the statement-carrying session event. This storage
    # harness checks the durable refresh path; the production READY route is covered below.
    second = await check_module.execute_check_commit(check_app, request)
    assert type(second).__name__ == "CheckCommitResult"
    assert check_app.calls == 2
    assert check_app.provider_calls == 1
    assert getattr(second, "semantic_status") is SemanticStatus.UNAVAILABLE

    ledger, _objects = start_runtime.resources[created.task_id]
    operation = await ledger.lookup_operation(created.writer_id, request.request_id)
    assert operation is not None
    assert operation.state.value == "complete"
    assert operation.suspension_kind is None


@pytest.mark.anyio
async def test_ready_same_request_recovery_after_statement_plan_amendment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """READY routing keeps the original check binding while a plan supplies its statement."""

    workspace = (tmp_path / "review-input-workspace").resolve()
    workspace.mkdir()
    provider = fireworks_provider(model="accounts/fireworks/models/minimax-m3")
    config = YoetzConfig(
        profile="local-openai",
        provider=provider,
    )
    async with multi_agent_service(tmp_path / "state", config=config) as service:
        deterministic_calls = 0
        provider_calls = 0
        original_deterministic = check_module.run_deterministic_policies

        def tracked_deterministic(
            case: DeterministicCase,
            scope: check_module.CheckScope,
            packs: tuple[str, ...],
            *,
            evaluators: dict[
                str, Callable[[DeterministicCase], tuple[DeterministicAssessment, ...]]
            ]
            | None = None,
        ) -> tuple[
            tuple[DeterministicAssessment, ...],
            tuple[CheckPolicyExecution, ...],
        ]:
            nonlocal deterministic_calls
            deterministic_calls += 1
            return original_deterministic(case, scope, packs, evaluators=evaluators)

        monkeypatch.setattr(check_module, "run_deterministic_policies", tracked_deterministic)
        policy_store = service.app.privacy.policy_application.policy_store  # type: ignore[union-attr]
        widened = minimal_external_policy()
        installation_id: str | None = None
        original_effective_policy = policy_store.effective_policy

        async def effective_policy(
            _store: object, scope: AuthorizationScope
        ) -> EffectivePrivacyPolicy:
            nonlocal installation_id
            installation_id = scope.installation_id
            if scope.kind is AuthorizationScopeKind.TASK:
                return EffectivePrivacyPolicy(widened, 2, widened.policy_digest)
            return await original_effective_policy(scope)

        monkeypatch.setattr(type(policy_store), "effective_policy", effective_policy)

        def fake_build_evaluator(
            _factory: OpenAIResponsesExternalFactory,
            binding: ProviderBinding,
            _credential: object,
            _request_commitment: object,
        ) -> object:
            async def evaluate(_case: object, _deadline: object) -> SemanticResultSuccess:
                nonlocal provider_calls
                provider_calls += 1
                provenance = ProviderAttemptProvenance(
                    provider=binding.provider_id,
                    endpoint_profile_id=binding.endpoint_profile_id,
                    endpoint_profile_version=binding.endpoint_profile_version,
                    model=binding.model_id,
                    sdk_version="test-gateway-1.0.0",
                    prompt_digest="sha256:" + "1" * 64,
                    schema_digest="sha256:" + "2" * 64,
                    policy_digest=widened.policy_digest,
                    privacy_policy_digest=widened.policy_digest,
                    sampling_params=SamplingParams(128),
                    latency_ms=1,
                    status=SemanticStatus.SUCCEEDED,
                    provider_request_id="review-input-test-provider-request",
                    request_commitment="hmac-sha256:" + "7" * 64,
                )
                return SemanticResultSuccess(
                    SemanticJudgment("no_material_discrepancy", ()), provenance
                )

            return SimpleNamespace(evaluate=evaluate)

        monkeypatch.setattr(OpenAIResponsesExternalFactory, "build_evaluator", fake_build_evaluator)
        lookup = service.vault.installation_mac_handle(MacKeyPurpose.CATALOG_LOOKUP)
        repository = await resolve_repository_privacy_context(
            WorkspaceLocator(str(workspace)), lookup
        )
        observation = LocalObservationStore(_state=service.root / "state")
        observation.grant_consent(observation.workspace_commitment(str(workspace)))
        common = {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "actor": {"actor_id": "harness:review-input-ready", "actor_type": "harness"},
            "client": {
                "kind": "cooperative_agent",
                "version": "0.3.0",
                "integration": "cooperative_mcp",
            },
        }
        started = await service.app.start(
            StartRequest.model_validate(
                {
                    **common,
                    "request_id": new_id(IdKind.REQUEST),
                    "mode": "create",
                    "task_title": "READY review input recovery",
                    "workspace_ref": str(workspace),
                    "external_ref": "review-input-ready",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=repository,
        )
        request = CheckRequest.model_validate(
            {
                **common,
                "request_id": new_id(IdKind.REQUEST),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": started.frontier.model_dump(mode="json"),
                "mode": "semantic_required",
                "max_findings": "3",
                "policy_packs": ["work-integrity/0.3.0"],
            }
        )
        first = await service.app.check(request, repository_privacy_context=repository)
        assert type(first).__name__ == "CheckAwaitingHuman"
        assert getattr(first, "state") == "awaiting_input"
        assert getattr(first, "continuation").kind == "review_input_required"

        statement = "Review the complete requested behavior and verify the final implementation."
        published = await service.app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **common,
                    "request_id": new_id(IdKind.REQUEST),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": started.frontier.model_dump(mode="json"),
                    "event_drafts": [
                        {
                            "event_id": new_id(IdKind.EVENT),
                            "schema": {"name": "plan_published", "version": "1.1.0"},
                            "occurred_at": "2026-09-05T12:00:00.000Z",
                            "causal_parents": [],
                            "payload": {
                                "plan_version": 1,
                                "summary": "Supply the complete user request before review.",
                                "obligation_refs": [],
                                "task_statement": statement,
                            },
                            "artifact_refs": [],
                            "evidence_refs": [],
                        }
                    ],
                }
            ),
            repository_privacy_context=repository,
        )
        assert isinstance(published, PublishWorkInternalResult)

        assert installation_id is not None
        policy_app = service.app.privacy.policy_application
        assert policy_app is not None
        repository_scope = AuthorizationScope(
            AuthorizationScopeKind.WORKSPACE,
            installation_id,
            repository.commitment,
        )
        authority = await policy_app.policy_store.repository_authority(repository_scope)
        candidate_policy = replace(
            widened,
            effective_scope=repository_scope,
            created_at=service.clock.now_utc(),
        )
        proposed = await privacy_propose_policy(
            policy_app,
            ProposePrivacyPolicyRequest(
                authority.effective.effective_digest,
                candidate_policy,
                authority.authority_digest,
                repository_scope,
            ),
        )
        assert isinstance(proposed, PolicyDecisionRequired)
        committed = await decide_privacy_policy(
            policy_app,
            DecidePrivacyPolicyRequest(
                proposed.prepared,
                HumanPolicyDecision(
                    proposed.prepared.prepared_digest,
                    True,
                    service.clock.now_utc(),
                    "hmac-sha256:" + "8" * 64,
                ),
                HumanAuthorityCapability(
                    "established_passphrase",
                    "sha256:" + "9" * 64,
                    1,
                    str(getattr(service.vault.mode, "value", service.vault.mode)),
                    service.vault.generation,
                    True,
                ),
            ),
        )
        assert committed.policy.effective_scope == repository_scope
        assert committed.policy.profile is widened.profile
        assert committed.policy.review_selection == widened.review_selection
        credential_binding = provider_credential_profile_binding(
            provider.provider_id,
            provider.model,
            provider.endpoint_profile_id,
            provider.endpoint_profile_version,
        )
        credential = service.memory.capture(
            SecretPurpose.PROVIDER_CREDENTIAL,
            bytearray(b"review-input-test-provider-token"),
        )
        await service.vault.store_provider_credential(
            "set",
            credential_binding,
            credential,
            HumanAuthorizationProof(
                "review-input-provider-credential",
                "provider_credential_set",
                credential_binding.target_digest("set"),
                1,
                service.vault.generation,
                None,
                1.0,
                60.0,
            ),
            2.0,
        )

        second = await service.app.check(request, repository_privacy_context=repository)
        assert type(second).__name__ == "CheckCommitResult"
        assert second.semantic_status is SemanticStatus.SUCCEEDED
        assert second.semantic_reason is SemanticReason.SEMANTIC_COMPLETED
        assert second.review_input_manifest is not None
        assert second.review_input_manifest["phase"] == "provider_bound"
        specification = second.review_input_manifest["specification"]
        assert isinstance(specification, JsonObject)
        assert specification["status"] == "complete"
        assert (
            specification["content_digest"]
            == "sha256:" + hashlib.sha256(statement.encode("utf-8")).hexdigest()
        )
        assert specification["content_bytes"] == len(statement.encode("utf-8"))
        assert specification["revision"] == 2
        assert provider_calls == 1
        assert getattr(second, "request_id") == request.request_id
        assert deterministic_calls >= 2

        # A completed provider-bound check must survive the durable history projection and the
        # ordinary-client privacy projection.  This is the native-host failure boundary: the
        # event stores the manifest as recursively frozen JSON, while the v1.4 history model
        # needs ordinary nested mappings for Pydantic validation.
        history_wire: dict[str, JsonValue] = {
            **common,
            "request_id": new_id(IdKind.REQUEST),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "view": "history",
            "limit": "10",
            "at_frontier": str(second.result_frontier.sequence),
        }
        history_request = StatusRequest.model_validate(history_wire)
        history = await service.app.status(history_request, repository_privacy_context=repository)
        history_page = history.page
        assert isinstance(history_page, StatusHistoryPageModel)
        check_items = [item for item in history_page.items if item.schema_name == "check_recorded"]
        assert len(check_items) == 1
        check_item = check_items[0]
        assert isinstance(check_item, StatusHistoryItemV14Model)
        assert check_item.review_input_manifest is not None
        assert check_item.review_input_manifest.phase == "provider_bound"
        assert check_item.review_input_manifest.specification.status == "complete"

        facts = await service.app.projection_binding_facts(
            ControlMethod.STATUS, history_wire, history
        )
        rpc_id = new_id(IdKind.CONTROL_RPC)
        service_instance_id = new_id(IdKind.SERVICE_INSTANCE)
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
        projected = await service.app.project_result_for_client(
            ClientProjectionContext(
                ControlClientKind.MCP_BRIDGE,
                ProjectionRenderMode.MACHINE_READABLE,
                False,
            ),
            binding,
            history,
        )
        assert isinstance(projected, StatusResultModel)
        assert isinstance(projected.root.page, StatusHistoryPageModel)
        projected_check_items = [
            item for item in projected.root.page.items if item.schema_name == "check_recorded"
        ]
        assert len(projected_check_items) == 1
        projected_check = projected_check_items[0]
        assert isinstance(projected_check, StatusHistoryItemV14Model)
        assert projected_check.review_input_manifest is not None
        assert projected_check.review_input_manifest.phase == "provider_bound"


async def _project(
    service: MultiAgentService,
    method: ControlMethod,
    wire: Mapping[str, JsonValue],
    value: UnprojectedControlBody,
) -> object:
    facts = await service.app.projection_binding_facts(method, wire, value)
    rpc_id = new_id(IdKind.CONTROL_RPC)
    service_instance_id = new_id(IdKind.SERVICE_INSTANCE)
    binding = ControlProjectionBinding(
        rpc_id,
        method,
        service_instance_id,
        1,
        facts.original_request_id,
        facts.route_identity_digest,
        canonical_encode(
            {
                "rpc_id": rpc_id,
                "method": method.value,
                "service_instance_id": service_instance_id,
                "service_generation": "1",
            }
        ),
    )
    return await service.app.project_result_for_client(
        ClientProjectionContext(
            ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
        ),
        binding,
        value,
    )


async def _project_status_views(
    service: MultiAgentService,
    common: Mapping[str, JsonValue],
    session_id: str,
    writer_id: str,
    repository: RepositoryPrivacyContext,
    check_request_id: str,
) -> None:
    views: tuple[tuple[str, dict[str, JsonValue]], ...] = (
        ("compact", {}),
        ("operation", {"filter": {"operation_request_id": check_request_id}}),
        ("history", {}),
        ("findings", {}),
        ("results", {}),
    )
    for view, extra in views:
        wire: dict[str, JsonValue] = {
            **common,
            "request_id": new_id(IdKind.REQUEST),
            "session_id": session_id,
            "writer_id": writer_id,
            "view": view,
            "limit": "10",
            **extra,
        }
        result = await service.app.status(
            StatusRequest.model_validate(wire), repository_privacy_context=repository
        )
        projected = await _project(service, ControlMethod.STATUS, wire, result)
        assert isinstance(projected, StatusResultModel), view


async def test_paused_and_recovered_check_project_for_mcp_clients(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A review-input pause and its recovery project through the MCP client boundary.

    Regression: the awaiting_input CHECK body and the STATUS operation page that replays its
    continuation failed public-model validation (preflight integers typed as wire strings; no
    review-input continuation branch in status-result 1.4.0), so agents saw INTERNAL_ERROR
    instead of the instruction to supply a task statement and never reached a review.
    """

    workspace = (tmp_path / "review-input-workspace").resolve()
    workspace.mkdir()
    provider = fireworks_provider(model="accounts/fireworks/models/minimax-m3")
    config = YoetzConfig(
        profile="local-openai",
        provider=provider,
    )
    async with multi_agent_service(tmp_path / "state", config=config) as service:
        deterministic_calls = 0
        provider_calls = 0
        original_deterministic = check_module.run_deterministic_policies

        def tracked_deterministic(
            case: DeterministicCase,
            scope: check_module.CheckScope,
            packs: tuple[str, ...],
            *,
            evaluators: dict[
                str, Callable[[DeterministicCase], tuple[DeterministicAssessment, ...]]
            ]
            | None = None,
        ) -> tuple[
            tuple[DeterministicAssessment, ...],
            tuple[CheckPolicyExecution, ...],
        ]:
            nonlocal deterministic_calls
            deterministic_calls += 1
            return original_deterministic(case, scope, packs, evaluators=evaluators)

        monkeypatch.setattr(check_module, "run_deterministic_policies", tracked_deterministic)
        policy_store = service.app.privacy.policy_application.policy_store  # type: ignore[union-attr]
        widened = minimal_external_policy()
        installation_id: str | None = None
        original_effective_policy = policy_store.effective_policy

        async def effective_policy(
            _store: object, scope: AuthorizationScope
        ) -> EffectivePrivacyPolicy:
            nonlocal installation_id
            installation_id = scope.installation_id
            if scope.kind is AuthorizationScopeKind.TASK:
                return EffectivePrivacyPolicy(widened, 2, widened.policy_digest)
            return await original_effective_policy(scope)

        monkeypatch.setattr(type(policy_store), "effective_policy", effective_policy)

        def fake_build_evaluator(
            _factory: OpenAIResponsesExternalFactory,
            binding: ProviderBinding,
            _credential: object,
            _request_commitment: object,
        ) -> object:
            async def evaluate(_case: object, _deadline: object) -> SemanticResultSuccess:
                nonlocal provider_calls
                provider_calls += 1
                provenance = ProviderAttemptProvenance(
                    provider=binding.provider_id,
                    endpoint_profile_id=binding.endpoint_profile_id,
                    endpoint_profile_version=binding.endpoint_profile_version,
                    model=binding.model_id,
                    sdk_version="test-gateway-1.0.0",
                    prompt_digest="sha256:" + "1" * 64,
                    schema_digest="sha256:" + "2" * 64,
                    policy_digest=widened.policy_digest,
                    privacy_policy_digest=widened.policy_digest,
                    sampling_params=SamplingParams(128),
                    latency_ms=1,
                    status=SemanticStatus.SUCCEEDED,
                    provider_request_id="review-input-test-provider-request",
                    request_commitment="hmac-sha256:" + "7" * 64,
                )
                return SemanticResultSuccess(
                    SemanticJudgment("no_material_discrepancy", ()), provenance
                )

            return SimpleNamespace(evaluate=evaluate)

        monkeypatch.setattr(OpenAIResponsesExternalFactory, "build_evaluator", fake_build_evaluator)
        lookup = service.vault.installation_mac_handle(MacKeyPurpose.CATALOG_LOOKUP)
        repository = await resolve_repository_privacy_context(
            WorkspaceLocator(str(workspace)), lookup
        )
        observation = LocalObservationStore(_state=service.root / "state")
        observation.grant_consent(observation.workspace_commitment(str(workspace)))
        common = {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "actor": {"actor_id": "harness:review-input-ready", "actor_type": "harness"},
            "client": {
                "kind": "cooperative_agent",
                "version": "0.3.0",
                "integration": "cooperative_mcp",
            },
        }
        started = await service.app.start(
            StartRequest.model_validate(
                {
                    **common,
                    "request_id": new_id(IdKind.REQUEST),
                    "mode": "create",
                    "task_title": "READY review input recovery",
                    "workspace_ref": str(workspace),
                    "external_ref": "review-input-ready",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=repository,
        )
        request = CheckRequest.model_validate(
            {
                **common,
                "request_id": new_id(IdKind.REQUEST),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": started.frontier.model_dump(mode="json"),
                "mode": "semantic_required",
                "max_findings": "3",
                "policy_packs": ["work-integrity/0.3.0"],
            }
        )
        first = await service.app.check(request, repository_privacy_context=repository)
        assert type(first).__name__ == "CheckAwaitingHuman"
        assert getattr(first, "state") == "awaiting_input"
        assert getattr(first, "continuation").kind == "review_input_required"

        wire_request = request.model_dump(mode="json", by_alias=True)
        paused = await _project(service, ControlMethod.CHECK, wire_request, first)
        assert isinstance(paused, CheckResultModel)
        await _project_status_views(
            service,
            common,
            started.session_id,
            started.writer_id,
            repository,
            request.request_id,
        )

        statement = "Review the complete requested behavior and verify the final implementation."
        published = await service.app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **common,
                    "request_id": new_id(IdKind.REQUEST),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": started.frontier.model_dump(mode="json"),
                    "event_drafts": [
                        {
                            "event_id": new_id(IdKind.EVENT),
                            "schema": {"name": "plan_published", "version": "1.1.0"},
                            "occurred_at": "2026-09-05T12:00:00.000Z",
                            "causal_parents": [],
                            "payload": {
                                "plan_version": 1,
                                "summary": "Supply the complete user request before review.",
                                "obligation_refs": [],
                                "task_statement": statement,
                            },
                            "artifact_refs": [],
                            "evidence_refs": [],
                        }
                    ],
                }
            ),
            repository_privacy_context=repository,
        )
        assert isinstance(published, PublishWorkInternalResult)

        assert installation_id is not None
        policy_app = service.app.privacy.policy_application
        assert policy_app is not None
        repository_scope = AuthorizationScope(
            AuthorizationScopeKind.WORKSPACE,
            installation_id,
            repository.commitment,
        )
        authority = await policy_app.policy_store.repository_authority(repository_scope)
        candidate_policy = replace(
            widened,
            effective_scope=repository_scope,
            created_at=service.clock.now_utc(),
        )
        proposed = await privacy_propose_policy(
            policy_app,
            ProposePrivacyPolicyRequest(
                authority.effective.effective_digest,
                candidate_policy,
                authority.authority_digest,
                repository_scope,
            ),
        )
        assert isinstance(proposed, PolicyDecisionRequired)
        committed = await decide_privacy_policy(
            policy_app,
            DecidePrivacyPolicyRequest(
                proposed.prepared,
                HumanPolicyDecision(
                    proposed.prepared.prepared_digest,
                    True,
                    service.clock.now_utc(),
                    "hmac-sha256:" + "8" * 64,
                ),
                HumanAuthorityCapability(
                    "established_passphrase",
                    "sha256:" + "9" * 64,
                    1,
                    str(getattr(service.vault.mode, "value", service.vault.mode)),
                    service.vault.generation,
                    True,
                ),
            ),
        )
        assert committed.policy.effective_scope == repository_scope
        assert committed.policy.profile is widened.profile
        assert committed.policy.review_selection == widened.review_selection
        credential_binding = provider_credential_profile_binding(
            provider.provider_id,
            provider.model,
            provider.endpoint_profile_id,
            provider.endpoint_profile_version,
        )
        credential = service.memory.capture(
            SecretPurpose.PROVIDER_CREDENTIAL,
            bytearray(b"review-input-test-provider-token"),
        )
        await service.vault.store_provider_credential(
            "set",
            credential_binding,
            credential,
            HumanAuthorizationProof(
                "review-input-provider-credential",
                "provider_credential_set",
                credential_binding.target_digest("set"),
                1,
                service.vault.generation,
                None,
                1.0,
                60.0,
            ),
            2.0,
        )

        second = await service.app.check(request, repository_privacy_context=repository)
        assert type(second).__name__ == "CheckCommitResult"
        assert getattr(second, "request_id") == request.request_id
        terminal = await _project(service, ControlMethod.CHECK, wire_request, second)
        assert isinstance(terminal, CheckResultModel)
        await _project_status_views(
            service,
            common,
            started.session_id,
            started.writer_id,
            repository,
            request.request_id,
        )


async def test_review_after_statement_revision_with_carried_obligation_commits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A statement supplied by revising a plan that already has obligations still commits.

    Regression: the carried obligations do not cite the new statement, so plan drift adds
    ``instruction_requirement_unmapped`` to ledger coverage. That task-level gap leaked into the
    evaluation's case-content gaps, which rejected it after a successful review, turning the
    check into a coordinator failure that agents only saw as OPERATION_PENDING. The review must
    commit and the gap must stay visible in the check coverage.
    """

    workspace = (tmp_path / "review-input-workspace").resolve()
    workspace.mkdir()
    provider = fireworks_provider(model="accounts/fireworks/models/minimax-m3")
    config = YoetzConfig(
        profile="local-openai",
        provider=provider,
    )
    async with multi_agent_service(tmp_path / "state", config=config) as service:
        deterministic_calls = 0
        provider_calls = 0
        original_deterministic = check_module.run_deterministic_policies

        def tracked_deterministic(
            case: DeterministicCase,
            scope: check_module.CheckScope,
            packs: tuple[str, ...],
            *,
            evaluators: dict[
                str, Callable[[DeterministicCase], tuple[DeterministicAssessment, ...]]
            ]
            | None = None,
        ) -> tuple[
            tuple[DeterministicAssessment, ...],
            tuple[CheckPolicyExecution, ...],
        ]:
            nonlocal deterministic_calls
            deterministic_calls += 1
            return original_deterministic(case, scope, packs, evaluators=evaluators)

        monkeypatch.setattr(check_module, "run_deterministic_policies", tracked_deterministic)
        policy_store = service.app.privacy.policy_application.policy_store  # type: ignore[union-attr]
        widened = minimal_external_policy()
        installation_id: str | None = None
        original_effective_policy = policy_store.effective_policy

        async def effective_policy(
            _store: object, scope: AuthorizationScope
        ) -> EffectivePrivacyPolicy:
            nonlocal installation_id
            installation_id = scope.installation_id
            if scope.kind is AuthorizationScopeKind.TASK:
                return EffectivePrivacyPolicy(widened, 2, widened.policy_digest)
            return await original_effective_policy(scope)

        monkeypatch.setattr(type(policy_store), "effective_policy", effective_policy)

        def fake_build_evaluator(
            _factory: OpenAIResponsesExternalFactory,
            binding: ProviderBinding,
            _credential: object,
            _request_commitment: object,
        ) -> object:
            async def evaluate(_case: object, _deadline: object) -> SemanticResultSuccess:
                nonlocal provider_calls
                provider_calls += 1
                provenance = ProviderAttemptProvenance(
                    provider=binding.provider_id,
                    endpoint_profile_id=binding.endpoint_profile_id,
                    endpoint_profile_version=binding.endpoint_profile_version,
                    model=binding.model_id,
                    sdk_version="test-gateway-1.0.0",
                    prompt_digest="sha256:" + "1" * 64,
                    schema_digest="sha256:" + "2" * 64,
                    policy_digest=widened.policy_digest,
                    privacy_policy_digest=widened.policy_digest,
                    sampling_params=SamplingParams(128),
                    latency_ms=1,
                    status=SemanticStatus.SUCCEEDED,
                    provider_request_id="review-input-test-provider-request",
                    request_commitment="hmac-sha256:" + "7" * 64,
                )
                return SemanticResultSuccess(
                    SemanticJudgment("no_material_discrepancy", ()), provenance
                )

            return SimpleNamespace(evaluate=evaluate)

        monkeypatch.setattr(OpenAIResponsesExternalFactory, "build_evaluator", fake_build_evaluator)
        lookup = service.vault.installation_mac_handle(MacKeyPurpose.CATALOG_LOOKUP)
        repository = await resolve_repository_privacy_context(
            WorkspaceLocator(str(workspace)), lookup
        )
        observation = LocalObservationStore(_state=service.root / "state")
        observation.grant_consent(observation.workspace_commitment(str(workspace)))
        common = {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "actor": {"actor_id": "harness:review-input-ready", "actor_type": "harness"},
            "client": {
                "kind": "cooperative_agent",
                "version": "0.3.0",
                "integration": "cooperative_mcp",
            },
        }
        started = await service.app.start(
            StartRequest.model_validate(
                {
                    **common,
                    "request_id": new_id(IdKind.REQUEST),
                    "mode": "create",
                    "task_title": "READY review input recovery",
                    "workspace_ref": str(workspace),
                    "external_ref": "review-input-ready",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=repository,
        )
        obligation = new_id(IdKind.OBLIGATION)
        planned = await service.app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **common,
                    "request_id": new_id(IdKind.REQUEST),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": started.frontier.model_dump(mode="json"),
                    "event_drafts": [
                        {
                            "event_id": new_id(IdKind.EVENT),
                            "schema": {"name": "obligation_published", "version": "1.0.0"},
                            "occurred_at": "2026-09-05T11:59:00.000Z",
                            "causal_parents": [],
                            "payload": {
                                "obligation_id": obligation,
                                "description": "Implement the feature.",
                                "evidence_expectation": "Tests pass.",
                                "status": "open",
                            },
                            "artifact_refs": [],
                            "evidence_refs": [],
                        },
                        {
                            "event_id": new_id(IdKind.EVENT),
                            "schema": {"name": "plan_published", "version": "1.0.0"},
                            "occurred_at": "2026-09-05T11:59:01.000Z",
                            "causal_parents": [],
                            "payload": {
                                "plan_version": 1,
                                "summary": "Implement it.",
                                "obligation_refs": [obligation],
                            },
                            "artifact_refs": [],
                            "evidence_refs": [],
                        },
                    ],
                }
            ),
            repository_privacy_context=repository,
        )
        assert isinstance(planned, PublishWorkInternalResult)
        planned_frontier = dict(planned.result_frontier.as_wire().items())
        request = CheckRequest.model_validate(
            {
                **common,
                "request_id": new_id(IdKind.REQUEST),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": planned_frontier,
                "mode": "semantic_required",
                "max_findings": "3",
                "policy_packs": ["work-integrity/0.3.0"],
            }
        )
        first = await service.app.check(request, repository_privacy_context=repository)
        assert type(first).__name__ == "CheckAwaitingHuman"
        assert getattr(first, "state") == "awaiting_input"
        assert getattr(first, "continuation").kind == "review_input_required"

        wire_request = request.model_dump(mode="json", by_alias=True)
        paused = await _project(service, ControlMethod.CHECK, wire_request, first)
        assert isinstance(paused, CheckResultModel)
        await _project_status_views(
            service,
            common,
            started.session_id,
            started.writer_id,
            repository,
            request.request_id,
        )

        statement = "Review the complete requested behavior and verify the final implementation."
        published = await service.app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **common,
                    "request_id": new_id(IdKind.REQUEST),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": planned_frontier,
                    "event_drafts": [
                        {
                            "event_id": new_id(IdKind.EVENT),
                            "schema": {"name": "plan_revised", "version": "1.1.0"},
                            "occurred_at": "2026-09-05T12:00:00.000Z",
                            "causal_parents": [],
                            "payload": {
                                "plan_version": 2,
                                "supersedes_plan_version": 1,
                                "reason": "Record the user request.",
                                "summary": "Supply the complete user request before review.",
                                "obligation_changes": [
                                    {"obligation_id": obligation, "change": "carried"}
                                ],
                                "task_statement": statement,
                            },
                            "artifact_refs": [],
                            "evidence_refs": [],
                        }
                    ],
                }
            ),
            repository_privacy_context=repository,
        )
        assert isinstance(published, PublishWorkInternalResult)

        assert installation_id is not None
        policy_app = service.app.privacy.policy_application
        assert policy_app is not None
        repository_scope = AuthorizationScope(
            AuthorizationScopeKind.WORKSPACE,
            installation_id,
            repository.commitment,
        )
        authority = await policy_app.policy_store.repository_authority(repository_scope)
        candidate_policy = replace(
            widened,
            effective_scope=repository_scope,
            created_at=service.clock.now_utc(),
        )
        proposed = await privacy_propose_policy(
            policy_app,
            ProposePrivacyPolicyRequest(
                authority.effective.effective_digest,
                candidate_policy,
                authority.authority_digest,
                repository_scope,
            ),
        )
        assert isinstance(proposed, PolicyDecisionRequired)
        committed = await decide_privacy_policy(
            policy_app,
            DecidePrivacyPolicyRequest(
                proposed.prepared,
                HumanPolicyDecision(
                    proposed.prepared.prepared_digest,
                    True,
                    service.clock.now_utc(),
                    "hmac-sha256:" + "8" * 64,
                ),
                HumanAuthorityCapability(
                    "established_passphrase",
                    "sha256:" + "9" * 64,
                    1,
                    str(getattr(service.vault.mode, "value", service.vault.mode)),
                    service.vault.generation,
                    True,
                ),
            ),
        )
        assert committed.policy.effective_scope == repository_scope
        assert committed.policy.profile is widened.profile
        assert committed.policy.review_selection == widened.review_selection
        credential_binding = provider_credential_profile_binding(
            provider.provider_id,
            provider.model,
            provider.endpoint_profile_id,
            provider.endpoint_profile_version,
        )
        credential = service.memory.capture(
            SecretPurpose.PROVIDER_CREDENTIAL,
            bytearray(b"review-input-test-provider-token"),
        )
        await service.vault.store_provider_credential(
            "set",
            credential_binding,
            credential,
            HumanAuthorizationProof(
                "review-input-provider-credential",
                "provider_credential_set",
                credential_binding.target_digest("set"),
                1,
                service.vault.generation,
                None,
                1.0,
                60.0,
            ),
            2.0,
        )

        second = await service.app.check(request, repository_privacy_context=repository)
        assert type(second).__name__ == "CheckCommitResult"
        assert getattr(second, "request_id") == request.request_id
        assert getattr(second, "semantic_status") is SemanticStatus.SUCCEEDED
        assert "instruction_requirement_unmapped" in getattr(second, "coverage").known_gaps
        terminal = await _project(service, ControlMethod.CHECK, wire_request, second)
        assert isinstance(terminal, CheckResultModel)
        await _project_status_views(
            service,
            common,
            started.session_id,
            started.writer_id,
            repository,
            request.request_id,
        )
