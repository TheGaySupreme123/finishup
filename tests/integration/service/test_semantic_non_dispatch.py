from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import yoetz.observability.diagnostics as diagnostics_module
import yoetz.service.ready_composition as ready_composition_module
from builders.ledger_adapters import (
    FixedClock,
    append_command,
    memory_adapter,
    ownership_fence,
    sqlite_adapter,
)
from builders.policy_cases import (
    FRONTIER,
    clm,
    evd,
    evidence_record,
    evt,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
)
from yoetz.adapters.memory.ledger import MemoryLedgerAdapter
from yoetz.adapters.sqlite.repository import SqliteLedger
from yoetz.application.check import (
    CheckScope,
    FinalSemanticEvaluation,
    allocate_findings,
    prior_finding_ids,
    run_deterministic_policies,
    semantic_coverage_gap_code,
)
from yoetz.application.egress import (
    PrivacyCoordinator,
    RepositoryGrantAdmission,
    SemanticEgressAwaitingHuman,
    SemanticEgressBlocked,
    SemanticEgressProviderOutcome,
)
from yoetz.application.semantic_content import CapturedContentResolution
from yoetz.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
)
from yoetz.domain.findings import (
    Finding,
    FindingKind,
    SamplingParams,
    SemanticDispatchKind,
    SemanticFailureClass,
)
from yoetz.domain.observation_profiles import CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    ChannelPolicy,
    DataClass,
    EgressChannel,
    PrivacyOutcome,
    PrivacyPolicy,
    PrivacyProfile,
    PrivacyReason,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from yoetz.domain.receipts import (
    SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP,
    SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,
    SEMANTIC_REVIEW_NOT_CONFIGURED_GAP,
)
from yoetz.domain.values import EvidenceId, timestamp_from_string
from yoetz.kernel.deterministic_checks import CaseGap, FindingBasisRef
from yoetz.kernel.projections import EvidenceProjectionRecord
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.importer import ImporterPort
from yoetz.ports.ledger import CheckPhase, FrozenCase, OperationLease
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectSource, ObjectStorePort
from yoetz.ports.privacy import (
    EffectivePrivacyPolicy,
    OutboundGatewayPort,
    PrivacyAuditPort,
    PrivacyClassifierPort,
    PrivacyPolicyStorePort,
    RepositoryPrivacyAuthority,
)
from yoetz.ports.runtime import TaskRuntime
from yoetz.ports.semantic import ProviderAttemptProvenance, SemanticResultUnavailable
from yoetz.ports.start_catalog import (
    SessionBinding,
    StartCatalogPort,
    TaskRoute,
    TaskRouteState,
)
from yoetz.protocol.canonical import canonical_digest, canonical_encode
from yoetz.protocol.coverage import EvidenceImmutability
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import DataCategory, SemanticReason, SemanticStatus
from yoetz.service.semantic_ceiling import ChannelAdmission

_TASK = "tsk_53000000-0000-4000-8000-000000000001"
_SESSION = "ses_53000000-0000-4000-8000-000000000001"
_WRITER = "wri_53000000-0000-4000-8000-000000000001"
_REQUEST = "req_53000000-0000-4000-8000-000000000001"
_INSTALLATION = "ins_53000000-0000-4000-8000-000000000001"
_REPOSITORY = "hmac-sha256:" + "b" * 64
_OBSERVATION_WORKSPACE = "hmac-sha256:" + "a" * 64
_OBSERVATION_SESSION = "hmac-sha256:" + "c" * 64
_PROVIDER = ProviderBinding(
    "sensitive-provider",
    "model",
    "endpoint-profile",
    "1.0.0",
    "external",
)

type _SemanticEvaluator = Callable[
    [FrozenCase, tuple[object, ...]], Awaitable[FinalSemanticEvaluation]
]
type _DurableSemanticEvaluator = Callable[
    [FrozenCase, tuple[object, ...], TaskRuntime], Awaitable[FinalSemanticEvaluation]
]


def _test_effective_policy(
    profile: ReviewContextProfile = ReviewContextProfile.STRUCTURAL,
) -> EffectivePrivacyPolicy:
    scope = AuthorizationScope(
        AuthorizationScopeKind.TASK,
        _INSTALLATION,
        _REPOSITORY,
        _TASK,
    )

    def _disabled(channel: EgressChannel) -> ChannelPolicy:
        return ChannelPolicy(
            channel,
            False,
            (),
            (),
            None,
            (),
            AuthorizationScopeKind.MACHINE,
            False,
            0,
            0,
            0,
        )

    policy = PrivacyPolicy(
        policy_id="pvy_53000000-0000-4000-8000-000000000001",
        version=1,
        policy_digest="sha256:" + "c" * 64,
        profile=PrivacyProfile.LOCAL_ONLY,
        review_context_profile=profile,
        review_selection=ReviewSelectionPolicy.for_profile(profile),
        require_current_provider_data_use_evidence=False,
        network_egress_permitted=False,
        effective_scope=scope,
        channel_policies=tuple(
            _disabled(channel) for channel in sorted(EgressChannel, key=lambda c: c.value)
        ),
        local_model_enabled=False,
        local_model_binding=None,
        local_model_categories=(),
        local_model_data_classes=(),
        agent_context_categories=(DataCategory.FINDING_SUMMARY,),
        agent_context_data_classes=(DataClass.ORDINARY_USER_CONTENT, DataClass.PUBLIC_STRUCTURAL),
        trusted_human_control_categories=tuple(DataCategory),
        trusted_human_control_data_classes=(
            DataClass.ORDINARY_USER_CONTENT,
            DataClass.PUBLIC_STRUCTURAL,
        ),
        created_at=datetime(2030, 1, 1, tzinfo=UTC),
    )
    return EffectivePrivacyPolicy(policy, 1, policy.policy_digest)


class _PolicyStore:
    def __init__(self, effective: EffectivePrivacyPolicy, *, repository_granted: bool) -> None:
        self._effective = effective
        self._repository_granted = repository_granted

    async def effective_policy(self, scope: AuthorizationScope) -> EffectivePrivacyPolicy:
        del scope
        return self._effective

    async def repository_authority(self, scope: AuthorizationScope) -> RepositoryPrivacyAuthority:
        grant_policy = None
        grant_generation = None
        grant_policy_digest = None
        if self._repository_granted:
            grant_policy = replace(
                self._effective.policy,
                effective_scope=AuthorizationScope(
                    AuthorizationScopeKind.WORKSPACE,
                    _INSTALLATION,
                    _REPOSITORY,
                ),
                policy_digest="sha256:" + "e" * 64,
            )
            grant_generation = 1
            grant_policy_digest = grant_policy.policy_digest
        return RepositoryPrivacyAuthority(
            scope=scope,
            effective=self._effective,
            repository_privacy_commitment=_REPOSITORY,
            grant_state="granted" if self._repository_granted else "missing",
            migration_state="not_applicable",
            authority_digest="sha256:" + "f" * 64,
            ancestors=(),
            grant_generation=grant_generation,
            grant_policy_digest=grant_policy_digest,
            grant_policy=grant_policy,
        )

    def set_repository_granted(self, granted: bool) -> None:
        self._repository_granted = granted


class _PolicyApplication:
    def __init__(self, effective: EffectivePrivacyPolicy, *, repository_granted: bool) -> None:
        self.policy_store = _PolicyStore(effective, repository_granted=repository_granted)


class _Privacy:
    def __init__(
        self,
        *,
        repository_granted: bool = True,
        task_id: str = _TASK,
        profile: ReviewContextProfile = ReviewContextProfile.STRUCTURAL,
    ) -> None:
        self.calls = 0
        self.resume_calls = 0
        self.repository_granted = repository_granted
        self.task_id = task_id
        # Real policy path is required for dispatch; never mint synthetic policy identity.
        self.policy_application = _PolicyApplication(
            _test_effective_policy(profile), repository_granted=repository_granted
        )
        self.terminal_provider_result = False
        self.resume_terminal: tuple[PrivacyOutcome, PrivacyReason] | None = None
        self.cancel_on_resume = False
        self.candidates: list[CandidateContext] = []

    async def activate_repository(self, scope: AuthorizationScope) -> bool:
        assert scope == AuthorizationScope(
            AuthorizationScopeKind.TASK,
            _INSTALLATION,
            _REPOSITORY,
            self.task_id,
        )
        return self.repository_granted

    async def admit_repository_grant(self, scope: AuthorizationScope) -> RepositoryGrantAdmission:
        policy_application = cast(
            _PolicyApplication | None, getattr(self, "policy_application", None)
        )
        if policy_application is None:
            return RepositoryGrantAdmission.UNAVAILABLE
        try:
            authority = await policy_application.policy_store.repository_authority(scope)
        except Exception:
            return RepositoryGrantAdmission.UNAVAILABLE
        if (
            type(authority) is not RepositoryPrivacyAuthority
            or authority.scope != scope
            or authority.repository_privacy_commitment != scope.workspace_ref_commitment
        ):
            return RepositoryGrantAdmission.UNAVAILABLE
        if authority.grant_state == "missing":
            return RepositoryGrantAdmission.MISSING
        if authority.grant_state != "granted":
            return RepositoryGrantAdmission.UNAVAILABLE
        try:
            activated = await self.activate_repository(scope)
        except Exception:
            return RepositoryGrantAdmission.UNAVAILABLE
        return (
            RepositoryGrantAdmission.GRANTED if activated else RepositoryGrantAdmission.UNAVAILABLE
        )

    async def evaluate_semantic(self, candidate: object, deadline: object) -> object:
        del deadline
        self.calls += 1
        if type(candidate) is CandidateContext:
            self.candidates.append(candidate)
        request_id = cast(str, getattr(candidate, "request_id"))
        if self.terminal_provider_result:
            return SemanticEgressProviderOutcome(
                request_id=request_id,
                privacy_proposal_id="ppr_53000000-0000-4000-8000-000000000002",
                authorization_id="aut_53000000-0000-4000-8000-000000000003",
                dispatch_kind=SemanticDispatchKind.EXTERNAL,
                result=SemanticResultUnavailable(
                    ProviderAttemptProvenance(
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
                        status=SemanticStatus.UNAVAILABLE,
                        failure_class=SemanticFailureClass.TRANSPORT,
                    )
                ),
                case_digest="sha256:" + "5" * 64,
                privacy_receipt_id="egr_53000000-0000-4000-8000-000000000004",
                request_commitment="hmac-sha256:" + "6" * 64,
            )
        return SemanticEgressAwaitingHuman(
            request_id,
            "ppr_53000000-0000-4000-8000-000000000001",
            "sha256:" + "a" * 64,
            datetime(2030, 1, 1, tzinfo=UTC),
        )

    async def resume(self, request_id: str, case_digest: str, deadline: object) -> object:
        del case_digest, deadline
        self.resume_calls += 1
        if self.cancel_on_resume:
            raise asyncio.CancelledError
        assert self.resume_terminal is not None
        outcome, reason = self.resume_terminal
        return SemanticEgressBlocked(
            request_id,
            outcome,
            reason,
            privacy_proposal_id="ppr_53000000-0000-4000-8000-000000000001",
        )


class _Catalog:
    def __init__(self, route: TaskRoute | None) -> None:
        self.route = route

    async def resolve_route(self, session: str) -> TaskRoute | None:
        assert self.route is None or session == self.route.session_id
        return self.route

    async def session_binding(self, session: str) -> SessionBinding | None:
        del session
        return None


def _route(state: TaskRouteState = TaskRouteState.ACTIVE) -> TaskRoute:
    route_generation = 1
    bundle_relpath = f"tasks/{_TASK}"
    identity = canonical_digest(
        {
            "task_id": _TASK,
            "bundle_relpath": bundle_relpath,
            "route_generation": route_generation,
        }
    )
    return TaskRoute(
        _TASK,
        _SESSION,
        bundle_relpath,
        route_generation,
        state,
        identity,
        _REPOSITORY,
    )


def _frozen() -> FrozenCase:
    return FrozenCase(
        make_case(),
        OperationLease(
            _WRITER,
            _REQUEST,
            _SESSION,
            CheckPhase.LOCAL_READY,
            "owner-generation-1",
            "lease-owner-1",
            1,
            datetime(2030, 1, 1, tzinfo=UTC),
            FRONTIER,
            "sha256:" + "d" * 64,
        ),
    )


def _route_for(task_id: str, session_id: str) -> TaskRoute:
    route_generation = 1
    bundle_relpath = f"tasks/{task_id}"
    return TaskRoute(
        task_id,
        session_id,
        bundle_relpath,
        route_generation,
        TaskRouteState.ACTIVE,
        canonical_digest(
            {
                "task_id": task_id,
                "bundle_relpath": bundle_relpath,
                "route_generation": route_generation,
            }
        ),
        _REPOSITORY,
    )


class _RoutedObservation:
    def __init__(
        self,
        *,
        task_id: str = _TASK,
        session_id: str = _SESSION,
        route_task: str | None = None,
    ) -> None:
        self.task_id = task_id
        self.session_id = session_id
        self.route_task = task_id if route_task is None else route_task

    def workspace_for_yoetz_session(self, session_id: str) -> str | None:
        assert session_id == self.session_id
        return _OBSERVATION_WORKSPACE

    def observation_route_for_session(
        self, *, workspace: str, yoetz_session_id: str
    ) -> tuple[str, str, bool] | None:
        assert workspace == _OBSERVATION_WORKSPACE
        assert yoetz_session_id == self.session_id
        return (_OBSERVATION_SESSION, self.route_task, True)


class _AmbiguousObservation:
    def workspace_for_yoetz_session(self, _session: str) -> object:
        return (_OBSERVATION_WORKSPACE, "hmac-sha256:" + "d" * 64)

    def observation_route_for_session(
        self, *, workspace: str, yoetz_session_id: str
    ) -> tuple[str, str, bool]:
        del workspace, yoetz_session_id
        return (_OBSERVATION_SESSION, _TASK, True)


class _MissingRouteObservation:
    def workspace_for_yoetz_session(self, _session: str) -> str:
        return _OBSERVATION_WORKSPACE

    def observation_route_for_session(self, *, workspace: str, yoetz_session_id: str) -> None:
        del workspace, yoetz_session_id
        return None


class _CaptureFence:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls: list[tuple[str, str, tuple[str, ...]]] = []

    def content_capture_authority_is_current(
        self, workspace: str, generation: str, profiles: tuple[str, ...]
    ) -> bool:
        self.calls.append((workspace, generation, profiles))
        return self.allowed


def _runtime_with_observation(observation: object) -> TaskRuntime:
    return cast(
        TaskRuntime,
        SimpleNamespace(
            task_id=_TASK,
            session_id=_SESSION,
            observation=observation,
        ),
    )


def test_ready_semantic_content_binding_uses_verified_observation_workspace() -> None:
    runtime = _runtime_with_observation(_RoutedObservation())
    workspace_for_runtime = cast(
        Callable[[TaskRuntime], str | None],
        getattr(ready_composition_module, "_observation_workspace_for_runtime"),
    )

    assert workspace_for_runtime(runtime) == _OBSERVATION_WORKSPACE
    assert _OBSERVATION_WORKSPACE != _REPOSITORY


@pytest.mark.parametrize(
    "observation",
    (
        _RoutedObservation(route_task="tsk_53000000-0000-4000-8000-000000000099"),
        _AmbiguousObservation(),
        _MissingRouteObservation(),
    ),
    ids=("wrong-task", "ambiguous-workspace", "missing-route"),
)
def test_ready_semantic_content_binding_fails_closed_for_ambiguous_or_mismatched_route(
    observation: object,
) -> None:
    runtime = _runtime_with_observation(observation)
    workspace_for_runtime = cast(
        Callable[[TaskRuntime], str | None],
        getattr(ready_composition_module, "_observation_workspace_for_runtime"),
    )

    assert workspace_for_runtime(runtime) is None


@pytest.mark.anyio
@pytest.mark.parametrize("fence_allowed", (True, False), ids=("current", "revoked"))
async def test_ready_semantic_content_resolution_and_fence_use_observation_workspace(
    monkeypatch: pytest.MonkeyPatch,
    fence_allowed: bool,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    adapter = memory_adapter(append_command())
    frozen, runtime = await _durable_semantic_case(adapter)
    runtime = replace(
        runtime,
        observation=_RoutedObservation(task_id=runtime.task_id, session_id=runtime.session_id),
    )
    privacy = _Privacy(task_id=runtime.task_id)
    baseline = _test_effective_policy()
    assisted = replace(
        baseline.policy,
        review_context_profile=ReviewContextProfile.ASSISTED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED),
    )
    privacy.policy_application = _PolicyApplication(
        replace(baseline, policy=assisted), repository_granted=True
    )
    privacy.terminal_provider_result = True
    local_fence = _CaptureFence(allowed=fence_allowed)
    resolved: list[str] = []

    async def resolve_content(**kwargs: object) -> CapturedContentResolution:
        resolved.append(cast(str, kwargs["workspace_commitment"]))
        return CapturedContentResolution(
            None,
            (),
            (),
            "sha256:" + "e" * 64,
            (CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,),
            True,
        )

    monkeypatch.setattr(
        ready_composition_module,
        "resolve_captured_semantic_content",
        resolve_content,
    )

    async def resolve_provider() -> ProviderBinding:
        return _PROVIDER

    evaluator_factory = cast(
        Callable[..., _DurableSemanticEvaluator],
        getattr(ready_composition_module, "_privacy_gated_semantic_evaluator"),
    )
    evaluator = evaluator_factory(
        cast(PrivacyCoordinator, privacy),
        FixedClock(),
        _INSTALLATION,
        resolve_provider,
        cast(StartCatalogPort, _Catalog(_route_for(runtime.task_id, runtime.session_id))),
        ready_composition_module.IdPort(),
        local_observation=local_fence,
    )

    result = await evaluator(frozen, (), runtime)

    assert result.status is (
        SemanticStatus.UNAVAILABLE if fence_allowed else SemanticStatus.BLOCKED_BY_POLICY
    )
    assert resolved == [_OBSERVATION_WORKSPACE]
    assert local_fence.calls
    assert all(
        call
        == (
            _OBSERVATION_WORKSPACE,
            "sha256:" + "e" * 64,
            (CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,),
        )
        for call in local_fence.calls
    )
    assert privacy.calls == (3 if fence_allowed else 0)
    records = [
        json.loads(line)
        for line in diagnostics_module.diagnostic_log_path(root=tmp_path).read_text().splitlines()
    ]
    built = [row for row in records if row["operation"] == "semantic_case_built"]
    assert len(built) == 1
    assert built[0]["semantic_capture_parts_resolved"] == 0
    assert built[0]["semantic_diff_parts_resolved"] == 0
    assert built[0]["semantic_diff_excerpts_selected"] == 0
    assert built[0]["semantic_excerpt_bytes_selected"] >= 0
    # The approved Assisted limits ride beside the selection counts (issue #907 Phase 1b).
    assert built[0]["semantic_excerpt_count_approved"] == 16
    assert built[0]["semantic_excerpt_byte_approved"] == 131_072
    assert built[0]["semantic_excerpt_count_limit"] == 16
    assert built[0]["semantic_excerpt_byte_limit"] == 131_072


async def _durable_semantic_case(
    adapter: MemoryLedgerAdapter | SqliteLedger,
) -> tuple[FrozenCase, TaskRuntime]:
    command = append_command()
    await adapter.append_batch(command)
    frozen = await adapter.freeze_case(
        command.session_id,
        command.writer_id,
        1,
        _REQUEST,
        "sha256:" + "7" * 64,
    )
    assert type(frozen) is FrozenCase
    operation = await adapter.lookup_operation(command.writer_id, _REQUEST)
    assert operation is not None and operation.resume_object_ref is not None
    prior = operation.resume_object_ref
    local_canonical = canonical_encode(
        {
            "schema_version": "1.0.0",
            "request_id": _REQUEST,
            "request_digest": "sha256:" + "7" * 64,
            "task_id": command.task_id,
            "session_id": command.session_id,
            "writer_id": command.writer_id,
            "subject_frontier": frozen.case.frontier.as_wire(),
            "dependency_digest": frozen.lease.dependency_digest,
            "prior_resume": {
                "object_id": prior.object_id,
                "envelope_digest": prior.envelope_digest,
                "commitment": prior.commitment,
            },
            "policy_executions": (),
            "assessments": (),
        }
    )
    objects = cast(ObjectStorePort, adapter._objects)  # pyright: ignore[reportPrivateUsage]
    staged = await objects.stage(
        ObjectSource(data=local_canonical, declared_size=len(local_canonical)),
        ObjectMetadata(
            ObjectKind.DETERMINISTIC_RESULT,
            "application/vnd.yoetz.deterministic-result+json",
            command.task_id,
            datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
        ),
    )
    local_result = await objects.finalize(staged)
    lease = await adapter.advance_check_phase(
        frozen.lease,
        CheckPhase.RESERVED,
        CheckPhase.LOCAL_READY,
        local_result,
    )
    lease = await adapter.advance_check_phase(
        lease,
        CheckPhase.LOCAL_READY,
        CheckPhase.SEMANTIC_WAIT,
    )
    runtime = TaskRuntime(
        command.task_id,
        command.session_id,
        command.writer_id,
        frozenset(
            {
                RuntimeCapability.WRITE,
                RuntimeCapability.STRUCTURAL_READ,
                RuntimeCapability.PAYLOAD_READ,
                RuntimeCapability.SEMANTIC,
            }
        ),
        adapter,
        objects,
        cast(ImporterPort, object()),
        "0.1.0",
        "0.1.0",
        "0.1",
        "1.0.0",
        ownership_fence(),
    )
    return FrozenCase(frozen.case, lease), runtime


def _evaluator(
    privacy: _Privacy,
    resolver: Callable[[], ProviderBinding | None],
    route: TaskRoute | None,
) -> _SemanticEvaluator:
    async def resolve_provider() -> ProviderBinding | None:
        return resolver()

    factory = cast(
        "Callable[..., _SemanticEvaluator]",
        getattr(ready_composition_module, "_privacy_gated_semantic_evaluator"),
    )
    return factory(
        cast(PrivacyCoordinator, privacy),
        FixedClock(),
        _INSTALLATION,
        resolve_provider,
        cast(StartCatalogPort, _Catalog(route)),
        ready_composition_module.IdPort(),
    )


def _records(tmp_path: Path) -> tuple[Mapping[str, object], ...]:
    path = diagnostics_module.diagnostic_log_path(root=tmp_path)
    return tuple(
        cast(Mapping[str, object], json.loads(line))
        for line in path.read_text(encoding="ascii").splitlines()
        if line
    )


def _assert_record(tmp_path: Path, operation: str, reason: SemanticReason) -> None:
    records = tuple(row for row in _records(tmp_path) if row["operation"] != "semantic_case_built")
    assert records == (
        {
            "timestamp": records[0]["timestamp"],
            "correlation_id": records[0]["correlation_id"],
            "component": "semantic_composition",
            "operation": operation,
            "reason": reason.value,
            "request_id": _REQUEST,
        },
    )
    raw = diagnostics_module.diagnostic_log_path(root=tmp_path).read_text(encoding="ascii")
    assert "sensitive-provider" not in raw
    assert "payload" not in raw
    assert "exception" not in raw
    assert str(tmp_path) not in raw


@pytest.mark.anyio
async def test_missing_repository_grant_suspends_same_request_before_provider_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    privacy = _Privacy(repository_granted=False)
    provider_resolutions = 0

    def resolve() -> ProviderBinding | None:
        nonlocal provider_resolutions
        provider_resolutions += 1
        return _PROVIDER

    result = await _evaluator(privacy, resolve, _route())(_frozen(), ())

    assert (result.status, result.reason) == (
        SemanticStatus.AWAITING_HUMAN,
        SemanticReason.HUMAN_APPROVAL_REQUIRED,
    )
    assert result.continuation is not None
    assert result.continuation.kind == "repository_privacy_setup"
    assert result.continuation.command == ("yoetz", "--privacy")
    assert result.continuation.request_id == _REQUEST
    assert provider_resolutions == 0
    assert privacy.calls == 0
    _assert_record(
        tmp_path,
        "semantic_suspended_repository_grant_missing",
        SemanticReason.HUMAN_APPROVAL_REQUIRED,
    )


@pytest.mark.anyio
async def test_exact_same_request_resumes_after_trusted_grant_to_terminal_provider_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    privacy = _Privacy(repository_granted=False)
    provider_resolutions = 0

    def resolve() -> ProviderBinding | None:
        nonlocal provider_resolutions
        provider_resolutions += 1
        return _PROVIDER

    evaluator = _evaluator(privacy, resolve, _route())
    original = _frozen()
    suspended = await evaluator(original, ())

    assert suspended.status is SemanticStatus.AWAITING_HUMAN
    assert suspended.continuation is not None
    assert suspended.continuation.request_id == original.lease.operation_id == _REQUEST
    assert provider_resolutions == privacy.calls == 0

    privacy.repository_granted = True
    privacy.policy_application.policy_store.set_repository_granted(True)
    privacy.terminal_provider_result = True
    resumed = await evaluator(original, ())

    assert (resumed.status, resumed.reason) == (
        SemanticStatus.UNAVAILABLE,
        SemanticReason.TRANSPORT_UNAVAILABLE,
    )
    assert resumed.continuation is None
    assert provider_resolutions == privacy.calls == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "adapter_factory",
    (memory_adapter, sqlite_adapter),
    ids=("memory", "sqlite"),
)
@pytest.mark.parametrize(
    ("terminal", "expected"),
    (
        (
            (PrivacyOutcome.HUMAN_DENIED, PrivacyReason.HUMAN_DENIED),
            (SemanticStatus.HUMAN_DENIED, SemanticReason.HUMAN_DENIED),
        ),
        (
            (PrivacyOutcome.APPROVAL_EXPIRED, PrivacyReason.AUTHORIZATION_EXPIRED),
            (SemanticStatus.APPROVAL_EXPIRED, SemanticReason.HUMAN_APPROVAL_EXPIRED),
        ),
        (
            (PrivacyOutcome.BLOCKED_BY_POLICY, PrivacyReason.SCOPE_MISMATCH),
            (SemanticStatus.BLOCKED_BY_POLICY, SemanticReason.SCOPE_NOT_AUTHORIZED),
        ),
    ),
)
async def test_disclosure_wait_replay_uses_resume_and_terminalizes_one_exact_attempt(
    adapter_factory: Callable[[object], MemoryLedgerAdapter | SqliteLedger],
    terminal: tuple[PrivacyOutcome, PrivacyReason],
    expected: tuple[SemanticStatus, SemanticReason],
) -> None:
    command = append_command()
    adapter = adapter_factory(command)
    frozen, runtime = await _durable_semantic_case(adapter)
    privacy = _Privacy(task_id=runtime.task_id)
    evaluator = cast(
        Callable[[FrozenCase, tuple[object, ...], TaskRuntime], Awaitable[FinalSemanticEvaluation]],
        _evaluator(
            privacy,
            lambda: _PROVIDER,
            _route_for(runtime.task_id, runtime.session_id),
        ),
    )

    waiting = await evaluator(frozen, (), runtime)
    assert waiting.status is SemanticStatus.AWAITING_HUMAN
    assert waiting.operation_lease is not None
    job = await adapter.load_semantic_job(runtime.writer_id or "", _REQUEST)
    assert job is not None
    attempts = await adapter.list_semantic_attempts(job.job_id)
    assert len(attempts) == 1 and attempts[0].state == "started"
    original_attempt = attempts[0]

    privacy.resume_terminal = terminal
    resumed = await evaluator(
        FrozenCase(frozen.case, waiting.operation_lease),
        (),
        runtime,
    )

    assert (resumed.status, resumed.reason) == expected
    assert privacy.calls == 1
    assert privacy.resume_calls == 1
    terminal_job = await adapter.load_semantic_job(runtime.writer_id or "", _REQUEST)
    assert terminal_job is not None and terminal_job.state == "failed"
    terminal_attempts = await adapter.list_semantic_attempts(terminal_job.job_id)
    assert len(terminal_attempts) == 1
    assert terminal_attempts[0].attempt_id == original_attempt.attempt_id
    assert terminal_attempts[0].provider_request_id == original_attempt.provider_request_id
    assert terminal_attempts[0].state == "failed"
    wait = await adapter.load_disclosure_wait(runtime.writer_id or "", _REQUEST)
    assert wait is not None and wait.state == "resolved"


@pytest.mark.anyio
async def test_cancellation_while_resuming_a_wait_terminalizes_before_propagating() -> None:
    command = append_command()
    adapter = memory_adapter(command)
    frozen, runtime = await _durable_semantic_case(adapter)
    privacy = _Privacy(task_id=runtime.task_id)
    evaluator = cast(
        Callable[[FrozenCase, tuple[object, ...], TaskRuntime], Awaitable[FinalSemanticEvaluation]],
        _evaluator(
            privacy,
            lambda: _PROVIDER,
            _route_for(runtime.task_id, runtime.session_id),
        ),
    )
    waiting = await evaluator(frozen, (), runtime)
    assert waiting.operation_lease is not None
    privacy.cancel_on_resume = True

    with pytest.raises(asyncio.CancelledError):
        await evaluator(FrozenCase(frozen.case, waiting.operation_lease), (), runtime)

    job = await adapter.load_semantic_job(runtime.writer_id or "", _REQUEST)
    assert job is not None and job.state == "failed"
    assert job.terminal_code is SemanticReason.COORDINATOR_FAILURE
    attempts = await adapter.list_semantic_attempts(job.job_id)
    assert len(attempts) == 1 and attempts[0].state == "failed"
    wait = await adapter.load_disclosure_wait(runtime.writer_id or "", _REQUEST)
    assert wait is not None and wait.state == "resolved"
    assert privacy.calls == privacy.resume_calls == 1


@pytest.mark.anyio
async def test_sqlite_restart_mid_wait_recovers_the_same_attempt_and_resume_route() -> None:
    command = append_command()
    original = sqlite_adapter(command)
    frozen, runtime = await _durable_semantic_case(original)
    privacy = _Privacy(task_id=runtime.task_id)
    evaluator = cast(
        Callable[[FrozenCase, tuple[object, ...], TaskRuntime], Awaitable[FinalSemanticEvaluation]],
        _evaluator(
            privacy,
            lambda: _PROVIDER,
            _route_for(runtime.task_id, runtime.session_id),
        ),
    )
    waiting = await evaluator(frozen, (), runtime)
    assert waiting.operation_lease is not None

    original._db.execute(  # pyright: ignore[reportPrivateUsage]
        "UPDATE bundle_meta SET value='2' WHERE key='owner_generation'"
    )
    restarted = SqliteLedger(
        db=original._db,  # pyright: ignore[reportPrivateUsage]
        task_id=runtime.task_id,
        ownership_fence=ownership_fence(generation=2),
        clock=FixedClock(),
        ids=original._ids,  # pyright: ignore[reportPrivateUsage]
        objects=original._objects,  # pyright: ignore[reportPrivateUsage]
    )
    restarted_runtime = replace(
        runtime,
        ledger=restarted,
        fence=ownership_fence(generation=2),
    )
    recovered = await restarted.load_semantic_job(runtime.writer_id or "", _REQUEST)
    assert recovered is not None and recovered.state == "leased"
    recovered_attempts = await restarted.list_semantic_attempts(recovered.job_id)
    assert len(recovered_attempts) == 1 and recovered_attempts[0].state == "started"
    recovered_wait = await restarted.load_disclosure_wait(runtime.writer_id or "", _REQUEST)
    assert recovered_wait is not None and recovered_wait.state == "awaiting"
    reclaimed = await restarted.freeze_case(
        runtime.session_id,
        runtime.writer_id or "",
        1,
        _REQUEST,
        "sha256:" + "7" * 64,
    )
    assert type(reclaimed) is FrozenCase

    privacy.resume_terminal = (PrivacyOutcome.HUMAN_DENIED, PrivacyReason.HUMAN_DENIED)
    result = await evaluator(
        reclaimed,
        (),
        restarted_runtime,
    )

    assert (result.status, result.reason) == (
        SemanticStatus.HUMAN_DENIED,
        SemanticReason.HUMAN_DENIED,
    )
    terminal = await restarted.load_semantic_job(runtime.writer_id or "", _REQUEST)
    assert terminal is not None and terminal.state == "failed"
    attempts = await restarted.list_semantic_attempts(terminal.job_id)
    assert len(attempts) == 1
    assert attempts[0].attempt_id == recovered_attempts[0].attempt_id
    assert attempts[0].provider_request_id == recovered_attempts[0].provider_request_id
    assert privacy.calls == privacy.resume_calls == 1

    # A second crash after the terminal AI-powered review write but before the outer check commit must
    # recover that terminal answer without calling either privacy entrypoint again.
    assert result.operation_lease is not None
    original._db.execute(  # pyright: ignore[reportPrivateUsage]
        "UPDATE bundle_meta SET value='3' WHERE key='owner_generation'"
    )
    recovered_terminal = SqliteLedger(
        db=original._db,  # pyright: ignore[reportPrivateUsage]
        task_id=runtime.task_id,
        ownership_fence=ownership_fence(generation=3),
        clock=FixedClock(),
        ids=original._ids,  # pyright: ignore[reportPrivateUsage]
        objects=original._objects,  # pyright: ignore[reportPrivateUsage]
    )
    terminal_runtime = replace(
        runtime,
        ledger=recovered_terminal,
        fence=ownership_fence(generation=3),
    )
    terminal_reclaimed = await recovered_terminal.freeze_case(
        runtime.session_id,
        runtime.writer_id or "",
        1,
        _REQUEST,
        "sha256:" + "7" * 64,
    )
    assert type(terminal_reclaimed) is FrozenCase
    replayed = await evaluator(
        terminal_reclaimed,
        (),
        terminal_runtime,
    )
    assert (replayed.status, replayed.reason) == (
        SemanticStatus.HUMAN_DENIED,
        SemanticReason.HUMAN_DENIED,
    )
    replayed_wait = await recovered_terminal.load_disclosure_wait(runtime.writer_id or "", _REQUEST)
    assert replayed_wait is not None and replayed_wait.state == "resolved"
    assert privacy.calls == privacy.resume_calls == 1


class _ClosingGateway:
    async def close(self) -> None:
        return None


@pytest.mark.anyio
async def test_closed_real_coordinator_is_terminal_without_repository_setup_or_dispatch() -> None:
    coordinator = PrivacyCoordinator(
        cast(
            PrivacyPolicyStorePort, _PolicyStore(_test_effective_policy(), repository_granted=False)
        ),
        cast(PrivacyClassifierPort, object()),
        cast(PrivacyAuditPort, object()),
        cast(OutboundGatewayPort, _ClosingGateway()),
        FixedClock(),
        ready_composition_module.IdPort(),
    )
    await coordinator.close()
    provider_resolutions = 0

    def resolve() -> ProviderBinding | None:
        nonlocal provider_resolutions
        provider_resolutions += 1
        return _PROVIDER

    result = await _evaluator(cast(_Privacy, coordinator), resolve, _route())(_frozen(), ())

    assert (result.status, result.reason) == (
        SemanticStatus.BLOCKED_BY_POLICY,
        SemanticReason.SCOPE_NOT_AUTHORIZED,
    )
    assert result.continuation is None
    assert provider_resolutions == 0


@pytest.mark.anyio
@pytest.mark.parametrize(
    (
        "live_provider",
        "route",
        "status",
        "reason",
        "gap",
        "operation",
    ),
    (
        (
            None,
            _route(),
            SemanticStatus.UNAVAILABLE,
            SemanticReason.CREDENTIAL_UNAVAILABLE,
            SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,
            "semantic_not_dispatched_credential_unavailable",
        ),
        (
            _PROVIDER,
            None,
            SemanticStatus.NOT_CONFIGURED,
            SemanticReason.PROVIDER_NOT_CONFIGURED,
            SEMANTIC_REVIEW_NOT_CONFIGURED_GAP,
            "semantic_not_dispatched_route_inactive",
        ),
        (
            _PROVIDER,
            _route(TaskRouteState.QUARANTINED),
            SemanticStatus.NOT_CONFIGURED,
            SemanticReason.PROVIDER_NOT_CONFIGURED,
            SEMANTIC_REVIEW_NOT_CONFIGURED_GAP,
            "semantic_not_dispatched_route_inactive",
        ),
    ),
)
async def test_semantic_non_dispatch_records_exact_bounded_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    live_provider: ProviderBinding | None,
    route: TaskRoute | None,
    status: SemanticStatus,
    reason: SemanticReason,
    gap: str,
    operation: str,
) -> None:
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    privacy = _Privacy()
    evaluator = _evaluator(privacy, lambda: live_provider, route)

    result = await evaluator(_frozen(), ())

    assert (result.status, result.reason) == (status, reason)
    assert semantic_coverage_gap_code(result.status, result.reason) == gap
    assert privacy.calls == 0
    _assert_record(tmp_path, operation, reason)


@pytest.mark.anyio
async def test_provider_unbound_records_not_configured_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    evaluator = cast(
        _SemanticEvaluator,
        getattr(ready_composition_module, "_semantic_provider_unbound"),
    )

    result = await evaluator(_frozen(), ())

    assert (result.status, result.reason) == (
        SemanticStatus.NOT_CONFIGURED,
        SemanticReason.PROVIDER_NOT_CONFIGURED,
    )
    assert semantic_coverage_gap_code(result.status, result.reason) == (
        SEMANTIC_REVIEW_NOT_CONFIGURED_GAP
    )
    _assert_record(
        tmp_path,
        "semantic_not_dispatched_provider_unbound",
        SemanticReason.PROVIDER_NOT_CONFIGURED,
    )


@pytest.mark.anyio
async def test_provider_binding_is_re_resolved_without_rebuilding_evaluator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    privacy = _Privacy()
    connected: ProviderBinding | None = None

    def resolve() -> ProviderBinding | None:
        return connected

    evaluator = _evaluator(privacy, resolve, _route())
    unavailable = await evaluator(_frozen(), ())
    connected = _PROVIDER
    dispatched = await evaluator(_frozen(), ())

    assert (unavailable.status, unavailable.reason) == (
        SemanticStatus.UNAVAILABLE,
        SemanticReason.CREDENTIAL_UNAVAILABLE,
    )
    assert (dispatched.status, dispatched.reason) == (
        SemanticStatus.AWAITING_HUMAN,
        SemanticReason.HUMAN_APPROVAL_REQUIRED,
    )
    assert privacy.calls == 1
    assert [record["operation"] for record in _records(tmp_path)] == [
        "semantic_not_dispatched_credential_unavailable",
        "semantic_case_built",
    ]


@pytest.mark.anyio
async def test_provider_resolution_failure_stays_inside_composition_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    privacy = _Privacy()

    def resolve() -> ProviderBinding | None:
        raise RuntimeError("resolver-detail-must-not-leak")

    evaluator = _evaluator(privacy, resolve, _route())

    result = await evaluator(_frozen(), ())

    assert (result.status, result.reason) == (
        SemanticStatus.FAILED,
        SemanticReason.COORDINATOR_FAILURE,
    )
    assert semantic_coverage_gap_code(result.status, result.reason) == (
        SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP
    )
    records = _records(tmp_path)
    assert len(records) == 1
    assert records[0]["component"] == "semantic_composition"
    assert records[0]["operation"] == "semantic_evaluation_failed"
    assert records[0]["reason"] == "exception_runtime_error"
    assert records[0]["request_id"] == _REQUEST
    raw = diagnostics_module.diagnostic_log_path(root=tmp_path).read_text(encoding="ascii")
    assert "resolver-detail-must-not-leak" not in raw


@pytest.mark.anyio
@pytest.mark.parametrize(
    "failure_class",
    (
        "route_commitment_absent",
        "authority_capability_absent",
        "policy_store_failure",
        "invalid_effective_policy",
        "repository_mismatch",
        "coordinator_closed",
        "effective_policy_unbound",
        "reconcile_capability_absent",
        "reconciliation_failure",
    ),
)
async def test_only_explicit_trusted_missing_authority_advertises_repository_setup(
    failure_class: str,
) -> None:
    privacy = _Privacy(repository_granted=True)
    route = _route()
    provider_resolutions = 0

    def resolve() -> ProviderBinding | None:
        nonlocal provider_resolutions
        provider_resolutions += 1
        return _PROVIDER

    if failure_class == "route_commitment_absent":
        route = replace(route, repository_privacy_commitment=None)
    elif failure_class == "authority_capability_absent":
        object.__setattr__(privacy, "policy_application", None)
    elif failure_class in {"policy_store_failure", "invalid_effective_policy"}:

        async def authority_failure(scope: AuthorizationScope) -> RepositoryPrivacyAuthority:
            del scope
            raise RuntimeError(failure_class)

        privacy.policy_application.policy_store.repository_authority = authority_failure
    elif failure_class == "repository_mismatch":
        original = privacy.policy_application.policy_store.repository_authority

        async def mismatched(scope: AuthorizationScope) -> RepositoryPrivacyAuthority:
            authority = await original(scope)
            return replace(
                authority,
                scope=AuthorizationScope(
                    AuthorizationScopeKind.TASK,
                    _INSTALLATION,
                    _REPOSITORY,
                    "tsk_53000000-0000-4000-8000-000000000099",
                ),
            )

        privacy.policy_application.policy_store.repository_authority = mismatched
    elif failure_class in {
        "coordinator_closed",
        "effective_policy_unbound",
        "reconcile_capability_absent",
    }:

        async def activation_unavailable(scope: AuthorizationScope) -> bool:
            del scope
            return False

        privacy.activate_repository = activation_unavailable
    else:

        async def activation_failure(scope: AuthorizationScope) -> bool:
            del scope
            raise RuntimeError("reconciliation_failure")

        privacy.activate_repository = activation_failure

    result = await _evaluator(privacy, resolve, route)(_frozen(), ())

    assert (result.status, result.reason) == (
        SemanticStatus.BLOCKED_BY_POLICY,
        SemanticReason.SCOPE_NOT_AUTHORIZED,
    )
    assert result.continuation is None
    assert provider_resolutions == 0
    assert privacy.calls == 0


@pytest.mark.anyio
@pytest.mark.parametrize(
    "adapter_factory", (memory_adapter, sqlite_adapter), ids=("memory", "sqlite")
)
async def test_required_packet_capacity_refuses_before_job_and_provider(
    adapter_factory: Callable[[object], MemoryLedgerAdapter | SqliteLedger],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yoetz.application.semantic_case as semantic_case_module

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    monkeypatch.setattr(semantic_case_module, "MAX_EGRESS_ENVELOPE_BYTES", 1)
    adapter = adapter_factory(append_command())
    frozen, runtime = await _durable_semantic_case(adapter)
    privacy = _Privacy(task_id=runtime.task_id)
    evaluator = cast(
        _DurableSemanticEvaluator,
        _evaluator(
            privacy,
            lambda: _PROVIDER,
            _route_for(runtime.task_id, runtime.session_id),
        ),
    )
    result = await evaluator(frozen, (), runtime)
    assert (result.status, result.reason) == (
        SemanticStatus.FAILED,
        SemanticReason.CASE_CAPACITY_EXCEEDED,
    )
    assert result.provenance is None
    assert result.attempt_accounting is None
    assert privacy.calls == privacy.resume_calls == 0
    assert await adapter.load_semantic_job(runtime.writer_id or "", _REQUEST) is None
    _assert_record(
        tmp_path,
        "semantic_not_dispatched_case_envelope_unbounded",
        SemanticReason.CASE_CAPACITY_EXCEEDED,
    )


@pytest.mark.anyio
@pytest.mark.parametrize("stage", ["privacy_dispatch_entered", "response_mapping"])
async def test_dispatch_and_mapping_failures_keep_original_check_join(
    stage: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from yoetz.observability.semantic_context import semantic_check_request

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    adapter = memory_adapter(append_command())
    frozen, runtime = await _durable_semantic_case(adapter)
    privacy = _Privacy(task_id=runtime.task_id)

    async def failed_dispatch(candidate: object, deadline: object) -> object:
        assert semantic_check_request.get() == _REQUEST
        raise RuntimeError("PRIVATE_SENTINEL_case_contents")

    def failed_mapping(*args: object, **kwargs: object) -> object:
        raise ValueError("PRIVATE_SENTINEL_provider_response")

    if stage == "privacy_dispatch_entered":
        monkeypatch.setattr(privacy, "evaluate_semantic", failed_dispatch)
    else:
        monkeypatch.setattr(ready_composition_module, "_map_egress_to_final", failed_mapping)
    evaluator = cast(
        _DurableSemanticEvaluator,
        _evaluator(
            privacy,
            lambda: _PROVIDER,
            _route_for(runtime.task_id, runtime.session_id),
        ),
    )
    result = await evaluator(frozen, (), runtime)
    assert (result.status, result.reason) == (
        SemanticStatus.FAILED,
        SemanticReason.COORDINATOR_FAILURE,
    )
    assert result.provenance is None
    rows = _records(tmp_path)
    assert any(row["operation"] == f"semantic_attempt_{stage}_failed" for row in rows)
    assert all(row["request_id"] == _REQUEST for row in rows)
    assert "PRIVATE_SENTINEL" not in repr(rows)
    assert semantic_check_request.get() is None


@pytest.mark.anyio
async def test_lineage_capacity_refuses_before_job_and_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from yoetz.application.semantic_case import LineageSemanticCapacityExceeded

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)

    def refuse(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise LineageSemanticCapacityExceeded("lineage_semantic_input_too_large")

    monkeypatch.setattr(ready_composition_module, "build_semantic_case", refuse)
    adapter = memory_adapter(append_command())
    frozen, runtime = await _durable_semantic_case(adapter)
    privacy = _Privacy(task_id=runtime.task_id)
    evaluator = cast(
        _DurableSemanticEvaluator,
        _evaluator(
            privacy,
            lambda: _PROVIDER,
            _route_for(runtime.task_id, runtime.session_id),
        ),
    )
    result = await evaluator(frozen, (), runtime)
    assert (result.status, result.reason) == (
        SemanticStatus.FAILED,
        SemanticReason.CASE_CAPACITY_EXCEEDED,
    )
    assert result.provenance is None
    assert result.attempt_accounting is None
    assert privacy.calls == privacy.resume_calls == 0
    assert await adapter.load_semantic_job(runtime.writer_id or "", _REQUEST) is None
    _assert_record(
        tmp_path,
        "semantic_not_dispatched_lineage_capacity",
        SemanticReason.CASE_CAPACITY_EXCEEDED,
    )


class _FindingIds:
    def new(self, kind: IdKind) -> str:
        return new_id(kind)


def _wide_frozen(
    width: int, extra_refs: tuple[FindingBasisRef, ...] = ()
) -> tuple[FrozenCase, tuple[Finding, ...]]:
    """Ordinary task material plus one gap naming ``width`` subjects (issue #858 shape).

    The work-integrity pack turns the gap into one ``ledger_stale_or_incomplete`` finding whose
    subject tuple is ``width`` wide — the finding the native parent review failed on.
    """

    plan = plan_record(PlanPublishedPayload(1, "Ship the review packet", (obl(1),)), 1)
    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1), "Build the real packet", "tests pass", ObligationStatus.OPEN
        ),
        2,
    )
    claim = record(
        ClaimRecordedPayload(
            clm(1),
            ClaimKind.COMPLETION,
            "Work is complete",
            (evd(1),),
            obligation_refs=(obl(1),),
        ),
        3,
    )
    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {
        evd(1): evidence_record(
            EvidenceRecordedPayload(
                evd(1),
                EvidenceKind.TEST_RESULT,
                EvidenceImmutability.METADATA_ONLY,
                timestamp_from_string("2026-07-01T00:00:00.000Z"),
                description="test output: 1 failed assertion",
            ),
            4,
        )
    }
    subjects = tuple(sorted((clm(number) for number in range(100, 100 + width)), key=str.encode))
    case = make_case(
        plans={1: plan},
        obligations={obl(1): obligation},
        claims={clm(1): claim},
        evidence=evidence,
        extra_refs=(clm(1), obl(1), evd(1), *extra_refs),
        gaps=(CaseGap("missing_ref:bulk", "missing_ref", subjects),),
    )
    assessments, _ = run_deterministic_policies(
        case, CheckScope((), ()), ("research-evidence/0.2.0", "work-integrity/0.3.0")
    )
    findings = allocate_findings(
        _FindingIds(),
        tuple(item.candidate for item in assessments),
        prior_finding_ids(case.projection),
    )
    wide = [item for item in findings if item.kind is FindingKind.LEDGER_STALE_OR_INCOMPLETE]
    assert len(wide) == 1 and len(wide[0].subject_refs) == width
    frozen = FrozenCase(
        case,
        OperationLease(
            _WRITER,
            _REQUEST,
            _SESSION,
            CheckPhase.LOCAL_READY,
            "owner-generation-1",
            "lease-owner-1",
            1,
            datetime(2030, 1, 1, tzinfo=UTC),
            FRONTIER,
            "sha256:" + "d" * 64,
        ),
    )
    return frozen, findings


@pytest.mark.anyio
async def test_a_reduced_case_records_no_included_references_it_did_not_send(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #904: only what a sent packet carried is recorded, never the builder's closure.

    The case's reference closure names refs that were only mentioned, linked or omitted. A review
    that never produced a result sent nothing the check may credit, so the final evaluation carries
    no included references even though its scope was reduced.
    """

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    privacy = _Privacy(profile=ReviewContextProfile.EXPANDED)
    privacy.terminal_provider_result = True
    unrelated = tuple(evt(900 + number) for number in range(4))
    frozen, findings = _wide_frozen(17, unrelated)

    result = await _evaluator(privacy, lambda: _PROVIDER, _route())(frozen, findings)

    [candidate] = privacy.candidates
    envelopes: list[dict[str, Any]] = []
    for item in candidate.items:
        if b'"frontier_refs"' not in item.plaintext:
            continue
        parsed: object = json.loads(item.plaintext)
        if isinstance(parsed, dict) and "frontier_refs" in parsed:
            envelopes.append(cast(dict[str, Any], parsed))
    [envelope] = envelopes
    assert int(cast(str, envelope["omitted_reference_count"])) >= len(unrelated)
    assert cast(list[str], envelope["frontier_refs"]), "the closure names references"
    assert result.status is SemanticStatus.UNAVAILABLE
    assert result.case_reference_scope_reduced is True
    assert result.case_included_refs is None


@pytest.mark.anyio
@pytest.mark.parametrize("width", (17, 21))
async def test_wide_finding_prose_dispatches_one_bounded_case(
    width: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Expanded review with a >16-subject finding reaches the provider once (issue #858).

    Before the fix the complete subject tuple reached ``SemanticCaseItem`` during case construction
    and the generic exception path reported ``failed / coordinator_failure`` with no dispatch. The
    bounded case now dispatches exactly once, names the omitted finding, and carries the capacity
    gap into the final evaluation the check result folds.
    """

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    privacy = _Privacy(profile=ReviewContextProfile.EXPANDED)
    privacy.terminal_provider_result = True
    frozen, findings = _wide_frozen(width)
    wide = next(item for item in findings if item.kind is FindingKind.LEDGER_STALE_OR_INCOMPLETE)
    wide_ref = str(wide.finding_id).encode("ascii")

    result = await _evaluator(privacy, lambda: _PROVIDER, _route())(frozen, findings)

    # The fake provider's terminal answer is what comes back: construction did not fail.
    assert (result.status, result.reason) == (
        SemanticStatus.UNAVAILABLE,
        SemanticReason.TRANSPORT_UNAVAILABLE,
    )
    assert privacy.calls == 1
    assert SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP in result.case_content_gaps
    assert not any(
        row.get("operation") == "semantic_evaluation_failed" for row in _records(tmp_path)
    )

    [candidate] = privacy.candidates
    item_ids = {item.item_id for item in candidate.items}
    assert f"finding-summary-{wide.finding_id}" not in item_ids
    assert f"finding-detail-{wide.finding_id}" not in item_ids
    # The other local findings of the run still travel with their prose.
    narrow = [item for item in findings if item.finding_id != wide.finding_id]
    assert narrow and all(f"finding-summary-{item.finding_id}" in item_ids for item in narrow)
    envelope = next(item.plaintext for item in candidate.items if item.item_id == "review-packet")
    assert wide_ref in envelope
    assert SEMANTIC_CASE_FINDING_REFS_OVER_LIMIT_GAP.encode("ascii") in envelope


@pytest.mark.anyio
@pytest.mark.parametrize("approval", ["current", "predates_section"])
async def test_task_statement_gap_or_item_reaches_the_final_evaluation(
    approval: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Criteria 1 and 7 (issue #908) through the real composition.

    A recorded statement travels as its own ``task_description`` candidate only under a policy
    that names the section; an approval that predates the section sends no statement at all and
    the final evaluation carries ``task_statement_unavailable`` with ``not_authorized``.
    """

    from yoetz.domain.task_statement import RecordedTaskStatement
    from yoetz.domain.values import event_id

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    privacy = _Privacy(profile=ReviewContextProfile.EXPANDED)
    privacy.terminal_provider_result = True
    if approval == "predates_section":
        store = privacy.policy_application.policy_store
        effective = store._effective  # pyright: ignore[reportPrivateUsage]
        legacy = replace(
            effective.policy,
            review_selection=ReviewSelectionPolicy.for_profile(
                ReviewContextProfile.EXPANDED, preset_version="1.1.0"
            ),
        )
        store._effective = replace(effective, policy=legacy)  # pyright: ignore[reportPrivateUsage]
    statement_event = event_id("evt_53000000-0000-4000-8000-000000000908")
    statement = "Under Ascii, Style.Truncate returns plain text without tail."
    base = _frozen()
    case = replace(
        make_case(extra_refs=(statement_event,)),
        task_statement=RecordedTaskStatement(statement, statement_event, "session_opened", 1),
        task_title="termenv",
    )
    frozen = replace(base, case=case)

    result = await _evaluator(privacy, lambda: _PROVIDER, _route())(frozen, ())

    assert privacy.calls == 1
    [candidate] = privacy.candidates
    carried = [item for item in candidate.items if item.item_id == "task-statement"]
    if approval == "current":
        assert [item.category for item in carried] == [DataCategory.TASK_DESCRIPTION]
        assert statement.encode() in carried[0].plaintext
        assert not {gap for gap in result.case_content_gaps if gap.startswith("task_statement")}
    else:
        assert carried == []
        assert all(statement.encode() not in item.plaintext for item in candidate.items)
        assert {"task_statement_not_authorized", "task_statement_unavailable"} <= set(
            result.case_content_gaps
        )


def _excerpt_heavy_frozen(count: int, description: str) -> FrozenCase:
    """A frozen case whose completion claim cites ``count`` evidence records (issue #907)."""

    from yoetz.protocol.coverage import EvidenceImmutability

    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {}
    for index in range(1, count + 1):
        evidence[evd(index)] = evidence_record(
            EvidenceRecordedPayload(
                evidence_id=evd(index),
                evidence_kind=EvidenceKind.TEST_RESULT,
                strength=EvidenceImmutability.METADATA_ONLY,
                observed_at=timestamp_from_string("2026-07-01T00:00:00.000Z"),
                description=description,
            ),
            index + 3,
        )
    claim = record(
        ClaimRecordedPayload(
            clm(1), ClaimKind.COMPLETION, "Work is complete", tuple(evidence), obligation_refs=()
        ),
        3,
    )
    case = make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Ship it", ()), 1)},
        claims={clm(1): claim},
        evidence=evidence,
        extra_refs=(clm(1), *evidence),
    )
    return replace(_frozen(), case=case)


def _with_channel_ceiling(monkeypatch: pytest.MonkeyPatch, limit: int) -> None:
    """Stand in for an enabled channel's ceiling; the fixture policy keeps its channel off.

    ``channel_prepared_limit`` itself is covered in ``tests/unit/service/test_semantic_ceiling.py``.
    """

    def fixed_limit(policy: object) -> int:
        del policy
        return limit

    monkeypatch.setattr(ready_composition_module, "channel_prepared_limit", fixed_limit)
    _with_full_admission(monkeypatch)


def _with_full_admission(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stand in for an enabled channel that releases every category it is offered."""

    def every_category(
        policy: object, bindings: Iterable[ProviderBinding | None]
    ) -> ChannelAdmission:
        del policy, bindings
        return ChannelAdmission(
            frozenset(DataCategory),
            frozenset(DataClass) - {DataClass.SECRET_OR_CRYPTOGRAPHIC},
        )

    monkeypatch.setattr(ready_composition_module, "channel_admission", every_category)


def _prepared_size(candidate: CandidateContext) -> int:
    from yoetz.application.semantic_case import assemble_filtered_review_packet
    from yoetz.protocol.canonical import strict_json_parse

    envelope = next(item.plaintext for item in candidate.items if item.item_id == "review-packet")
    return len(
        assemble_filtered_review_packet(
            cast(dict[str, object], strict_json_parse(envelope)),
            content_by_id={item.item_id: item.plaintext for item in candidate.items},
            included_item_ids={item.item_id for item in candidate.items},
        )
    )


@pytest.mark.anyio
async def test_expanded_1_2_0_counters_show_the_protocol_maximum_not_16(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #907 Phase 1b: 40 small items are all selected; the count limit reads 64."""

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    privacy = _Privacy(profile=ReviewContextProfile.EXPANDED)
    privacy.terminal_provider_result = True
    _with_channel_ceiling(monkeypatch, 262_144)

    await _evaluator(privacy, lambda: _PROVIDER, _route())(
        _excerpt_heavy_frozen(40, "test run: 12 passed, 0 failed"), ()
    )

    assert privacy.calls == 1
    [built] = [row for row in _records(tmp_path) if row["operation"] == "semantic_case_built"]
    assert built["semantic_excerpts_selected"] == 40
    assert built["semantic_excerpt_count_limit"] == 64
    assert built["semantic_excerpt_byte_limit"] == 131_072
    assert built["semantic_excerpt_ceiling_rounds"] == 0
    assert built["semantic_excerpt_count_cut_for_case_bound"] == 0


@pytest.mark.anyio
async def test_a_case_over_the_channel_ceiling_is_planned_below_it_and_disclosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #907 Phase 1b: more excerpts must not turn a runnable review into a denied one.

    Quote-heavy excerpts cost about twice their bytes once escaped, so 64 selectable excerpts
    would prepare a packet over 262,144 bytes that egress refuses whole. The case is rebuilt with
    a smaller excerpt byte budget instead, the dropped excerpts are disclosed as
    ``content_unselected``, and a replay builds the identical case.
    """

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    # About 8 KB per excerpt once escaped: excerpts carry their approved bytes rather than a 4 KiB
    # structural clip since #907 Phase 1a, so the fixture carries 4 KB of quotes itself.
    frozen = _excerpt_heavy_frozen(64, '"' * 4_000)
    digests: list[str] = []
    for _attempt in range(2):
        privacy = _Privacy(profile=ReviewContextProfile.EXPANDED)
        privacy.terminal_provider_result = True
        _with_channel_ceiling(monkeypatch, 262_144)

        result = await _evaluator(privacy, lambda: _PROVIDER, _route())(frozen, ())

        assert privacy.calls == 1
        [candidate] = privacy.candidates
        assert _prepared_size(candidate) <= 262_144
        assert "content_unselected" in result.case_content_gaps
        digests.append(str(candidate.subject_digest))
    built = [row for row in _records(tmp_path) if row["operation"] == "semantic_case_built"]
    assert len(built) == 2
    assert all(1 <= cast(int, row["semantic_excerpt_ceiling_rounds"]) <= 4 for row in built)
    assert all(16 < cast(int, row["semantic_excerpts_selected"]) < 64 for row in built)
    # Consent approved 64 excerpts and 128 KiB; the planner, not the owner, set the narrower
    # effective byte limit, and the diagnostics keep the two apart (R944-03).
    assert all(row["semantic_excerpt_count_approved"] == 64 for row in built)
    assert all(row["semantic_excerpt_byte_approved"] == 131_072 for row in built)
    assert all(cast(int, row["semantic_excerpt_byte_limit"]) < 131_072 for row in built)
    assert digests[0] == digests[1]


def _prose_heavy_frozen(
    excerpts: int, unsupported_claims: int
) -> tuple[FrozenCase, tuple[Finding, ...]]:
    """Unsupported claims whose findings carry 4 KiB clipped summary and detail prose, beside one
    claim that ``excerpts`` 2,000-byte evidence rows support (the R944-01 trigger)."""

    from yoetz.protocol.coverage import EvidenceImmutability

    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {}
    for index in range(1, excerpts + 1):
        evidence[evd(index)] = evidence_record(
            EvidenceRecordedPayload(
                evidence_id=evd(index),
                evidence_kind=EvidenceKind.TEST_RESULT,
                strength=EvidenceImmutability.METADATA_ONLY,
                observed_at=timestamp_from_string("2026-07-01T00:00:00.000Z"),
                description="e" * 2_000,
            ),
            index + 30,
        )
    claims = {
        clm(1): record(
            ClaimRecordedPayload(
                clm(1),
                ClaimKind.COMPLETION,
                "Work is complete",
                tuple(evidence),
                obligation_refs=(),
            ),
            3,
        )
    }
    for number in range(2, unsupported_claims + 2):
        claims[clm(number)] = record(
            ClaimRecordedPayload(
                clm(number), ClaimKind.COMPLETION, f"Claim {number}", (), obligation_refs=()
            ),
            number + 3,
        )
    case = make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Ship it", ()), 1)},
        claims=claims,
        evidence=evidence,
        extra_refs=(*claims, *evidence),
    )
    assessments, _ = run_deterministic_policies(
        case, CheckScope((), ()), ("research-evidence/0.2.0", "work-integrity/0.3.0")
    )
    findings = tuple(
        replace(finding, summary="s" * 8_192, detail="d" * 8_192)
        for finding in allocate_findings(
            _FindingIds(),
            tuple(item.candidate for item in assessments),
            prior_finding_ids(case.projection),
        )
    )
    return replace(_frozen(), case=case), findings


@pytest.mark.anyio
async def test_excerpts_cut_for_the_case_bound_are_their_own_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R944-01: the cut is reported apart from consent (approved) and planning (rounds, limit)."""

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    privacy = _Privacy(profile=ReviewContextProfile.EXPANDED)
    privacy.terminal_provider_result = True
    _with_channel_ceiling(monkeypatch, 262_144)
    frozen, findings = _prose_heavy_frozen(64, 18)

    result = await _evaluator(privacy, lambda: _PROVIDER, _route())(frozen, findings)

    assert result.reason is not SemanticReason.COORDINATOR_FAILURE
    assert privacy.calls == 1
    assert "content_unselected" in result.case_content_gaps
    [built] = [row for row in _records(tmp_path) if row["operation"] == "semantic_case_built"]
    assert built["semantic_excerpt_count_approved"] == 64
    assert cast(int, built["semantic_excerpt_count_cut_for_case_bound"]) > 0


@pytest.mark.anyio
async def test_fixed_material_over_the_case_bound_is_a_capacity_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without excerpts to cut, 32 findings' prose over the case bound is a typed refusal."""

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    privacy = _Privacy(profile=ReviewContextProfile.EXPANDED)
    _with_channel_ceiling(monkeypatch, 262_144)
    # The completion claim has no evidence either, so 31 unsupported claims give 32 findings.
    frozen, findings = _prose_heavy_frozen(0, 31)
    assert len(findings) == 32

    result = await _evaluator(privacy, lambda: _PROVIDER, _route())(frozen, findings)

    assert (result.status, result.reason) == (
        SemanticStatus.FAILED,
        SemanticReason.CASE_CAPACITY_EXCEEDED,
    )
    assert privacy.calls == 0
    _assert_record(
        tmp_path,
        "semantic_not_dispatched_case_capacity",
        SemanticReason.CASE_CAPACITY_EXCEEDED,
    )


@pytest.mark.anyio
async def test_the_planner_sizes_only_what_the_channel_releases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R944-02: excerpts the channel withholds cannot push the case over its ceiling.

    The same quote-heavy case that is planned down above is left whole when the channel releases
    only structural metadata: local minimization removes the excerpt bytes before egress, so they
    must not be traded away to fit a ceiling they never reach.
    """

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    privacy = _Privacy(profile=ReviewContextProfile.EXPANDED)
    privacy.terminal_provider_result = True
    _with_channel_ceiling(monkeypatch, 262_144)
    seen: list[tuple[ProviderBinding | None, ...]] = []

    def structural_only(
        policy: object, bindings: Iterable[ProviderBinding | None]
    ) -> ChannelAdmission:
        del policy
        seen.append(tuple(bindings))
        return ChannelAdmission(
            frozenset({DataCategory.BOUNDED_STRUCTURAL_METADATA}),
            frozenset({DataClass.PUBLIC_STRUCTURAL}),
        )

    monkeypatch.setattr(ready_composition_module, "channel_admission", structural_only)

    await _evaluator(privacy, lambda: _PROVIDER, _route())(
        _excerpt_heavy_frozen(64, '"' * 8_000), ()
    )

    assert privacy.calls == 1
    # The admission is taken for the destinations the case can be dispatched to.
    assert seen == [(_PROVIDER, None)]
    [built] = [row for row in _records(tmp_path) if row["operation"] == "semantic_case_built"]
    assert built["semantic_excerpt_ceiling_rounds"] == 0
    assert built["semantic_excerpt_byte_limit"] == built["semantic_excerpt_byte_approved"]


@pytest.mark.anyio
async def test_an_unset_custom_ceiling_still_plans_below_the_disclosure_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #907 Phase 1b: zero ``max_bytes``/``max_tokens`` mean unset, not unbounded.

    Without a bound the planner left a 64-excerpt case over the 262,144-byte disclosure limit,
    and preparing it failed as a coordinator error instead of a planned, disclosed review.
    """

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    privacy = _Privacy(profile=ReviewContextProfile.EXPANDED)
    privacy.terminal_provider_result = True
    store = privacy.policy_application.policy_store
    effective = store._effective  # pyright: ignore[reportPrivateUsage]
    custom = replace(effective.policy, review_context_profile=ReviewContextProfile.CUSTOM)
    assert all(
        (channel.max_bytes, channel.max_tokens) == (0, 0)
        for channel in custom.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )
    store._effective = replace(effective, policy=custom)  # pyright: ignore[reportPrivateUsage]
    # The fixture's channel is off; an unset ceiling is about an enabled one.
    _with_full_admission(monkeypatch)

    result = await _evaluator(privacy, lambda: _PROVIDER, _route())(
        _excerpt_heavy_frozen(64, '"' * 8_000), ()
    )

    assert result.reason is not SemanticReason.COORDINATOR_FAILURE
    assert privacy.calls == 1
    [candidate] = privacy.candidates
    assert _prepared_size(candidate) <= 262_144
    assert "content_unselected" in result.case_content_gaps
    [built] = [row for row in _records(tmp_path) if row["operation"] == "semantic_case_built"]
    assert cast(int, built["semantic_excerpt_ceiling_rounds"]) >= 1


@pytest.mark.anyio
@pytest.mark.parametrize("recorded", ["statement", "title_only"])
async def test_a_channel_that_withholds_task_description_says_the_statement_was_not_sent(
    recorded: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #908: the section is selected but the LLM channel will not let task_description out.

    The statement (or the title standing in) would be built and then filtered at egress, so a
    review could succeed without the user's request and say only that some context was withheld.
    The packet and the final evaluation name it instead: ``task_statement_unavailable`` with
    ``task_statement_not_authorized``, and no statement item is offered at all.
    """

    from builders.privacy_policies import minimal_external_policy
    from yoetz.domain.task_statement import RecordedTaskStatement
    from yoetz.domain.values import event_id

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    privacy = _Privacy(profile=ReviewContextProfile.EXPANDED)
    privacy.terminal_provider_result = True
    store = privacy.policy_application.policy_store
    effective = store._effective  # pyright: ignore[reportPrivateUsage]
    base = minimal_external_policy()
    blocked = replace(
        base,
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
            for channel in base.channel_policies
        ),
    )
    assert "task_statement" in blocked.review_selection.sections
    assert DataCategory.TASK_DESCRIPTION in blocked.withheld_review_categories
    store._effective = EffectivePrivacyPolicy(  # pyright: ignore[reportPrivateUsage]
        blocked, effective.generation, blocked.policy_digest
    )
    statement_event = event_id("evt_53000000-0000-4000-8000-000000000909")
    statement = "Under Ascii, Style.Truncate returns plain text without tail."
    case = replace(
        make_case(extra_refs=(statement_event,)),
        task_statement=(
            RecordedTaskStatement(statement, statement_event, "session_opened", 1)
            if recorded == "statement"
            else None
        ),
        task_title="termenv",
    )

    result = await _evaluator(privacy, lambda: _PROVIDER, _route())(
        replace(_frozen(), case=case), ()
    )

    assert privacy.calls == 1
    [candidate] = privacy.candidates
    assert [item for item in candidate.items if item.item_id == "task-statement"] == []
    assert {"task_statement_unavailable", "task_statement_not_authorized"} <= set(
        result.case_content_gaps
    )
    assert "task_statement_not_supplied" not in result.case_content_gaps
    envelope = next(item.plaintext for item in candidate.items if item.item_id == "review-packet")
    assert b"task_statement_not_authorized" in envelope
