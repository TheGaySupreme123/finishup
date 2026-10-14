"""Durable privacy pipeline and adapter isolation for ``PolicyEnforcingOutboundGateway``.

Exercises the gateway end to end against real domain/port value types: policy reconciliation
activating/deactivating adapters without restart, exact-body scanning and final validation before
credential exposure, atomic authorization consumption, and the local-model dispatch path. The
in-file ``_FullPrivacyAudit`` fake asserts (by raising) that the gateway calls only the exact audit
methods its contract allows, and the fake provider/local-model adapters assert they receive only an
``ApprovedProviderCase`` -- never a repository/object-store handle, environment, or policy authority.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac as hmac_module
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest

from yoetz.adapters.privacy.gateway import (
    PolicyEnforcingOutboundGateway,
    _with_policy_digest,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from yoetz.adapters.providers.factory import external_factory_builders_from_config
from yoetz.adapters.providers.fake import (
    FakeSemanticScript,
    ScriptedFakeSemanticEvaluator,
    scripted_success,
)
from yoetz.adapters.providers.local_model import (
    InstalledLocalModelProfileRegistry,
    LocalModelEndpointProfile,
)
from yoetz.adapters.providers.openai_responses_factory import provider_binding_from_config
from yoetz.config.write import anthropic_provider
from yoetz.domain.findings import RuntimeAttemptEvidence, SamplingParams, SemanticFailureClass
from yoetz.domain.privacy import (
    ApprovedLocalDisclosureCase,
    ApprovedOutboundCase,
    AuthorizationScope,
    AuthorizationScopeKind,
    ChannelPolicy,
    ConsentSource,
    DataCategory,
    DataClass,
    EgressAuthorization,
    EgressChannel,
    EgressReceipt,
    LocalDisclosureSink,
    PrivacyOutcome,
    PrivacyPolicy,
    PrivacyProfile,
    PrivacyReason,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from yoetz.observability.privacy import privacy_request_commitment
from yoetz.ports.privacy import (
    ConsumedAuthorization,
    ConsumedLocalDisclosure,
    EffectivePrivacyPolicy,
    HumanAuthorityCapability,
    ProviderReconciliation,
)
from yoetz.ports.secret_memory import ProviderAttemptAuthBinding
from yoetz.ports.semantic import (
    Deadline,
    ExternalRuntimeAuthority,
    ProviderAttemptProvenance,
    SemanticJudgment,
    SemanticResult,
    SemanticResultSuccess,
    SemanticResultUnavailable,
)
from yoetz.protocol.canonical import canonical_encode
from yoetz.protocol.ids import IdKind
from yoetz.protocol.models import SemanticStatus

_INSTALLATION = "ins_60000000-0000-4000-8000-000000000001"
_TASK = "tsk_60000000-0000-4000-8000-000000000002"
_WORKSPACE = f"hmac-sha256:{'6' * 64}"
_POLICY_ID = "pvy_60000000-0000-4000-8000-000000000003"
_PROPOSAL = "ppr_60000000-0000-4000-8000-000000000004"
_REQUEST = "req_60000000-0000-4000-8000-000000000005"
_DIGEST = f"sha256:{'a' * 64}"
_DIGEST_2 = f"sha256:{'b' * 64}"
_NOW = datetime(2026, 7, 19, tzinfo=UTC)

_PROVIDER_ID = "fake-provider"
_MODEL_ID = "fake-model-v1"
_ENDPOINT_ID = "ep-fake"
_ENDPOINT_VERSION = "1.0.0"


class _Clock:
    def __init__(self, *, utc: datetime = _NOW, monotonic: float = 100.0) -> None:
        self.utc = utc
        self.monotonic = monotonic

    def now_utc(self) -> datetime:
        return self.utc

    def monotonic_seconds(self) -> float:
        return self.monotonic


class _Ids:
    def __init__(self) -> None:
        self._n = 0

    def new(self, kind: IdKind) -> str:
        self._n += 1
        prefix = {IdKind.EGRESS_DISPATCH: "dsp_", IdKind.EGRESS_RECEIPT: "egr_"}[kind]
        return f"{prefix}{self._n:08x}-0000-4000-8000-000000000001"


class _AuditKey:
    """A deterministic ``MacKeyHandle`` stand-in; never a raw key/bytes value to callers."""

    def __init__(self, seed: bytes = b"k" * 32) -> None:
        self._seed = seed

    def mac(self, domain: bytes, message: bytes) -> str:
        digest = hmac_module.new(self._seed, domain + message, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"


@dataclass(slots=True)
class _CredentialRecord:
    consumed: bool = False


class _FakeCredentialHandle:
    """A single-use credential handle: its transport-callback contract is enforced here."""

    def __init__(self, token: bytes, record: _CredentialRecord) -> None:
        self._token = token
        self._record = record

    async def authorize_attempt(self, binding: object, inject_and_start: object) -> object:
        if self._record.consumed:
            raise RuntimeError("credential_already_consumed")
        self._record.consumed = True
        return await inject_and_start.inject_and_start(memoryview(self._token))  # type: ignore[attr-defined]


class _CredentialMinter:
    def __init__(self) -> None:
        self.mint_calls: list[ProviderAttemptAuthBinding] = []
        self.fail = False

    async def mint(self, binding: ProviderAttemptAuthBinding) -> _FakeCredentialHandle:
        self.mint_calls.append(binding)
        if self.fail:
            raise RuntimeError("simulated_credential_mint_failure")
        return _FakeCredentialHandle(b"fake-secret-token-0123456789", _CredentialRecord())


class _InjectCallback:
    def __init__(self) -> None:
        self.injected: bytes | None = None

    async def inject_and_start(self, credential_view: memoryview) -> None:
        self.injected = bytes(credential_view)


class _FakeEvaluator:
    """Consumes its credential exactly once, then defers to a scripted fake evaluation."""

    def __init__(self, script: FakeSemanticScript, credential: object, binding: object) -> None:
        self._inner = ScriptedFakeSemanticEvaluator(script)
        self._credential = credential
        self._binding = binding
        self.evaluate_calls = 0

    async def evaluate(self, case: object, deadline: object) -> object:
        self.evaluate_calls += 1
        callback = _InjectCallback()
        await self._credential.authorize_attempt(self._binding, callback)  # type: ignore[attr-defined]
        assert callback.injected == b"fake-secret-token-0123456789"
        return await self._inner.evaluate(case, deadline)  # type: ignore[arg-type]


class _FakeExternalFactory:
    """Credential-free external factory: renders deterministically, no I/O until dispatch."""

    def __init__(self, script_factory: object) -> None:
        self._script_factory = script_factory
        self.render_calls = 0
        self.rendered_bodies: list[bytes] = []
        self.built: list[_FakeEvaluator] = []
        self.closed = False

    def render(self, case: ApprovedOutboundCase) -> bytes:
        self.render_calls += 1
        # A tiny fixed reviewed template wraps the exact approved payload bytes only.
        body = b'{"template":"reviewed-schema/1","payload":' + case.payload + b"}"
        self.rendered_bodies.append(body)
        return body

    def build_evaluator(
        self, binding: object, credential: object, request_commitment: object
    ) -> object:
        del request_commitment
        evaluator = _FakeEvaluator(self._script_factory(), credential, binding)  # type: ignore[operator]
        self.built.append(evaluator)
        return evaluator

    async def close(self) -> None:
        self.closed = True


class _ForbiddenBodyFactory(_FakeExternalFactory):
    """Renders a body whose fixed template segment carries a never-send credential pattern."""

    def render(self, case: ApprovedOutboundCase) -> bytes:
        self.render_calls += 1
        body = b'{"payload":' + case.payload + b',"leak":"' + b"AKI" + b"AABCDEFGHIJKLMNOP" + b'"}'
        self.rendered_bodies.append(body)
        return body


class _HeuristicBodyFactory(_FakeExternalFactory):
    """Renders a body with an ambiguous dotted assignment that remains never-send."""

    def render(self, case: ApprovedOutboundCase) -> bytes:
        self.render_calls += 1
        body = b'{"payload":' + case.payload + b',"lookalike":"TOKEN=opaque.value"}'
        self.rendered_bodies.append(body)
        return body


class _RaisingEvaluatorFactory(_FakeExternalFactory):
    """A factory whose transport raises an ambiguous, native-text-bearing failure."""

    def build_evaluator(
        self, binding: object, credential: object, request_commitment: object
    ) -> object:
        del binding, credential, request_commitment

        class _Raiser:
            async def evaluate(self, case: object, deadline: object) -> object:
                del case, deadline
                raise RuntimeError("native-provider-socket-reset: 10.0.0.7:443 leaked")

        return _Raiser()


class _CancellingEvaluatorFactory(_FakeExternalFactory):
    """A factory whose transport is cancelled mid-attempt, after the consume CAS (issue #755)."""

    def build_evaluator(
        self, binding: object, credential: object, request_commitment: object
    ) -> object:
        del binding, credential, request_commitment

        class _Cancelled:
            async def evaluate(self, case: object, deadline: object) -> object:
                del case, deadline
                raise asyncio.CancelledError

        return _Cancelled()


class _LocalSocketHandle:
    def __init__(self, service_generation: int, profile_digest: str, response: bytes) -> None:
        self._service_generation = service_generation
        self._profile_digest = profile_digest
        self._response = response
        self.sent: list[bytes] = []
        self.closed = False

    @property
    def service_generation(self) -> int:
        return self._service_generation

    @property
    def profile_digest(self) -> str:
        return self._profile_digest

    async def send(self, payload: bytes) -> None:
        self.sent.append(payload)

    async def receive(self, max_bytes: int) -> bytes:
        del max_bytes
        return self._response

    def close(self) -> None:
        self.closed = True


class _LocalResolver:
    def __init__(self, handle: _LocalSocketHandle) -> None:
        self._handle = handle
        self.resolve_calls = 0

    def resolve(self, profile: LocalModelEndpointProfile) -> _LocalSocketHandle:
        del profile
        self.resolve_calls += 1
        return self._handle


class _FullPrivacyAudit:
    """A working in-memory ``PrivacyAuditPort`` limited to exactly the gateway's call surface.

    Every method the gateway must never call raises immediately, doubling as a network/authority
    spy: any accidental call to ``authorize``/``reserve``/``record_human_decision``/etc. fails the
    test loudly instead of silently succeeding.
    """

    def __init__(self) -> None:
        self._authorizations: dict[str, EgressAuthorization] = {}
        self._authorization_state: dict[str, str] = {}
        self._local_state: dict[str, str] = {}
        self.decision_receipts: list[tuple[str, EgressReceipt]] = []
        self.egress_receipts: list[tuple[str, EgressReceipt]] = []
        self.parked_receipts: list[tuple[str, EgressReceipt]] = []
        self.consume_local_calls: list[tuple[str, str]] = []

    def seed_authorized(self, authorization: EgressAuthorization) -> None:
        self._authorizations[authorization.authorization_id] = authorization
        self._authorization_state[authorization.authorization_id] = "authorized"

    def seed_local_reserved(self, privacy_proposal_id: str) -> None:
        self._local_state[privacy_proposal_id] = "reserved"

    def authorization_state(self, authorization_id: str) -> str | None:
        return self._authorization_state.get(authorization_id)

    async def consume(
        self, authorization_id: str, dispatch_id: str, now: datetime
    ) -> ConsumedAuthorization:
        if self._authorization_state.get(authorization_id) != "authorized":
            raise ValueError("privacy_audit_authorization_unavailable")
        self._authorization_state[authorization_id] = "consumed"
        return ConsumedAuthorization(self._authorizations[authorization_id], dispatch_id, now)

    async def complete_egress(self, dispatch_id: str, receipt: EgressReceipt) -> None:
        self.egress_receipts.append((dispatch_id, receipt))

    async def park_attempt_reconciliation(self, dispatch_id: str, receipt: EgressReceipt) -> None:
        self.parked_receipts.append((dispatch_id, receipt))

    async def complete_decision(self, reservation_id: str, receipt: EgressReceipt) -> None:
        self.decision_receipts.append((reservation_id, receipt))

    async def consume_local(
        self, reservation_id: str, approved_case_digest: str, now: datetime
    ) -> ConsumedLocalDisclosure:
        if self._local_state.get(reservation_id) != "reserved":
            raise ValueError("privacy_local_reservation_unavailable")
        self._local_state[reservation_id] = "consumed"
        self.consume_local_calls.append((reservation_id, approved_case_digest))
        return ConsumedLocalDisclosure(
            reservation_id, approved_case_digest, LocalDisclosureSink.LOCAL_MODEL, now
        )

    async def complete_agent_projection(self, request: object, receipt: object) -> object:
        raise AssertionError("gateway must never call complete_agent_projection")

    async def prepare_disclosure_proposal(self, request: object) -> object:
        raise AssertionError("gateway must never call prepare_disclosure_proposal")

    async def reserve(self, subject: object) -> object:
        raise AssertionError("gateway must never call reserve")

    async def load(self, request_id: str, subject_digest: str) -> object:
        raise AssertionError("gateway must never call load")

    async def load_disclosure_proposal(self, proposal_id: str) -> object:
        raise AssertionError("gateway must never call load_disclosure_proposal")

    async def load_authorization(self, authorization_id: str) -> object:
        raise AssertionError("gateway must never call load_authorization")

    async def record_human_decision(self, reservation_id: str, decision: object) -> object:
        raise AssertionError("gateway must never call record_human_decision")

    async def authorize(
        self, reservation_id: str, approved_case_digest: str, now: datetime
    ) -> object:
        raise AssertionError("gateway must never call authorize")

    async def complete_local_disclosure(self, reservation_id: str, receipt: object) -> None:
        raise AssertionError("gateway must never call complete_local_disclosure")

    async def get_receipt(self, receipt_id: str, audience: object) -> object:
        raise AssertionError("gateway must never call get_receipt")

    async def list_receipts(self, query: object, audience: object) -> object:
        raise AssertionError("gateway must never call list_receipts")

    async def revoke_policy_generation(self, generation: int, reason: str) -> int:
        raise AssertionError("gateway must never call revoke_policy_generation")

    async def live_object_roots(self, task_id: str, route_identity_digest: str) -> object:
        raise AssertionError("gateway must never call live_object_roots")


def _provider_binding() -> ProviderBinding:
    return ProviderBinding(_PROVIDER_ID, _MODEL_ID, _ENDPOINT_ID, _ENDPOINT_VERSION, "external")


def _local_binding() -> ProviderBinding:
    return ProviderBinding("local-svc", "local-model-v1", "ep-local", "1.0.0", "local_af_unix")


def _scope() -> AuthorizationScope:
    return AuthorizationScope(AuthorizationScopeKind.TASK, _INSTALLATION, _WORKSPACE, _TASK)


def _channel(
    channel: EgressChannel, *, enabled: bool, binding: ProviderBinding | None = None
) -> ChannelPolicy:
    if not enabled:
        return ChannelPolicy(
            channel, False, (), (), None, (), AuthorizationScopeKind.MACHINE, False, 0, 0, 0
        )
    return ChannelPolicy(
        channel,
        True,
        (DataCategory.TASK_DESCRIPTION,),
        (DataClass.ORDINARY_USER_CONTENT,),
        binding if binding is not None else _provider_binding(),
        ("selected-code-review",),
        AuthorizationScopeKind.TASK,
        False,
        65_536,
        4_096,
        3_600,
    )


def _policy(
    *,
    external_enabled: bool,
    local_enabled: bool,
    version: int = 1,
    digest: str = _DIGEST,
    binding: ProviderBinding | None = None,
) -> PrivacyPolicy:
    channels = tuple(
        _channel(
            channel,
            enabled=(channel is EgressChannel.LLM_INFERENCE and external_enabled),
            binding=binding,
        )
        for channel in sorted(EgressChannel, key=lambda item: item.value)
    )
    return PrivacyPolicy(
        policy_id=_POLICY_ID,
        version=version,
        policy_digest=digest,
        profile=PrivacyProfile.TRUSTED_PROVIDER if external_enabled else PrivacyProfile.LOCAL_ONLY,
        review_context_profile=ReviewContextProfile.STRUCTURAL,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        require_current_provider_data_use_evidence=False,
        network_egress_permitted=external_enabled,
        effective_scope=_scope(),
        channel_policies=channels,
        local_model_enabled=local_enabled,
        local_model_binding=_local_binding() if local_enabled else None,
        local_model_categories=(DataCategory.TASK_DESCRIPTION,) if local_enabled else (),
        local_model_data_classes=(DataClass.ORDINARY_USER_CONTENT,) if local_enabled else (),
        agent_context_categories=(),
        agent_context_data_classes=(),
        trusted_human_control_categories=(),
        trusted_human_control_data_classes=(),
        created_at=_NOW,
        supersedes_policy_digest=None if version == 1 else _DIGEST,
    )


def _human_authority(*, available: bool, service_generation: int = 1) -> HumanAuthorityCapability:
    return HumanAuthorityCapability(
        source="os_user_presence" if available else "unavailable",
        capability_digest=_DIGEST,
        service_generation=service_generation,
        vault_mode="os_keyring",
        vault_generation=1,
        external_activation_allowed=available,
    )


def _authorization(
    *,
    authorization_id: str,
    policy_digest: str,
    service_generation: int,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> EgressAuthorization:
    return EgressAuthorization(
        authorization_id=authorization_id,
        privacy_proposal_id=_PROPOSAL,
        case_digest=_DIGEST,
        channel=EgressChannel.LLM_INFERENCE,
        provider_binding=_provider_binding(),
        purpose="selected-code-review",
        scope=_scope(),
        policy_version=1,
        policy_digest=policy_digest,
        max_bytes=65_536,
        max_tokens=4_096,
        consent_source=ConsentSource.BASELINE_POLICY,
        issued_at=issued_at or (_NOW - timedelta(minutes=10)),
        expires_at=expires_at or (_NOW + timedelta(minutes=5)),
        service_generation=service_generation,
    )


def _case(
    *, case_id: str, authorization: EgressAuthorization, payload: bytes
) -> ApprovedOutboundCase:
    return ApprovedOutboundCase(
        case_id=case_id,
        request_id=_REQUEST,
        payload=payload,
        media_type="application/json",
        schema_id="yoetz.outbound-case-payload",
        included_item_ids=("item-1",),
        approved_categories=(DataCategory.TASK_DESCRIPTION,),
        blocked_categories=(),
        byte_count=len(payload),
        token_count=8,
        provider_binding=authorization.provider_binding,
        purpose=authorization.purpose,
        authorization_id=authorization.authorization_id,
        policy_digest=authorization.policy_digest,
        case_digest=authorization.case_digest,
    )


def _provenance(
    status: SemanticStatus,
    *,
    policy_digest: str,
    failure_class: SemanticFailureClass | None = None,
) -> ProviderAttemptProvenance:
    return ProviderAttemptProvenance(
        provider=_PROVIDER_ID,
        endpoint_profile_id=_ENDPOINT_ID,
        endpoint_profile_version=_ENDPOINT_VERSION,
        model=_MODEL_ID,
        sdk_version="0.0.0",
        prompt_digest=_DIGEST_2,
        schema_digest=_DIGEST_2,
        policy_digest=policy_digest,
        privacy_policy_digest=policy_digest,
        sampling_params=SamplingParams(128),
        latency_ms=1,
        status=status,
        failure_class=failure_class,
    )


def _deadline(clock: _Clock, *, remaining_seconds: float = 30.0) -> Deadline:
    return Deadline(_NOW + timedelta(minutes=5), clock.monotonic + remaining_seconds)


async def _repository_authority_current(_scope: object, _authority_digest: str) -> bool:
    return True


def _gateway(
    *,
    audit: _FullPrivacyAudit,
    clock: _Clock,
    credential_minter: _CredentialMinter | None = None,
    external_factory: object | None = None,
    external_factory_builder: object | None = None,
    local_registry: InstalledLocalModelProfileRegistry | None = None,
    local_resolver: _LocalResolver | None = None,
    repository_authority_validator: object | None = _repository_authority_current,
) -> PolicyEnforcingOutboundGateway:
    minter = credential_minter or _CredentialMinter()
    builders = {}
    if external_factory_builder is not None:
        builders[_provider_binding()] = external_factory_builder
    elif external_factory is not None:
        builders[_provider_binding()] = lambda: external_factory
    return PolicyEnforcingOutboundGateway(
        external_factory_builders=builders,  # type: ignore[arg-type]
        local_model_registry=local_registry or InstalledLocalModelProfileRegistry(),
        local_model_resolver=local_resolver,
        credential_minter=minter,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        classifier=LocalPrivacyEnforcer(),
        audit_mac=_AuditKey(),  # type: ignore[arg-type]
        clock=clock,  # type: ignore[arg-type]
        ids=_Ids(),  # type: ignore[arg-type]
        repository_authority_validator=repository_authority_validator,  # type: ignore[arg-type]
    )


async def _reconcile_repository(
    gateway: PolicyEnforcingOutboundGateway,
    effective: EffectivePrivacyPolicy,
    human: HumanAuthorityCapability,
) -> ProviderReconciliation:
    repository = effective.policy.effective_scope.workspace_ref_commitment
    assert repository is not None
    return await gateway.reconcile_repository_policy(
        effective,
        human,
        repository_privacy_commitment=repository,
        authority_digest=effective.effective_digest,
    )


def _script_factory() -> FakeSemanticScript:
    return FakeSemanticScript((scripted_success(SemanticJudgment("no_material_discrepancy", ())),))


def test_reconcile_and_dispatch_external_semantic_succeeds() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    minter = _CredentialMinter()
    factory = _FakeExternalFactory(_script_factory)
    gateway = _gateway(audit=audit, clock=clock, credential_minter=minter, external_factory=factory)
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)
    assert gateway.has_connected_provider_binding(_provider_binding()) is False

    async def run() -> tuple[SemanticResult, EgressAuthorization]:
        reconciliation = await _reconcile_repository(gateway, effective, human)
        assert reconciliation == ProviderReconciliation(1, 1, 0, ())
        assert gateway.has_connected_provider_binding(_provider_binding()) is True
        assert (
            gateway.has_connected_provider_binding(
                replace(_provider_binding(), model_id="different-model-same-provider")
            )
            is False
        )

        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000010",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        payload = canonical_encode({"note": "hello"})
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000011",
            authorization=authorization,
            payload=payload,
        )
        result = await gateway.dispatch_external_semantic(case, authorization, _deadline(clock))
        return result, authorization

    result, authorization = asyncio.run(run())

    assert type(result) is SemanticResultSuccess
    assert factory.render_calls == 1
    assert len(factory.built) == 1
    assert factory.built[0].evaluate_calls == 1
    assert len(minter.mint_calls) == 1
    assert audit.authorization_state(authorization.authorization_id) == "consumed"
    assert audit.decision_receipts == []
    assert len(audit.egress_receipts) == 1
    dispatch_id, receipt = audit.egress_receipts[0]
    assert receipt.outcome is PrivacyOutcome.COMPLETED
    assert receipt.safe_failure_reason is None
    assert receipt.authorization_id == authorization.authorization_id
    assert receipt.dispatch_id == dispatch_id
    assert dispatch_id.startswith("dsp_")
    assert receipt.request_commitment is not None
    rendered_body = factory.rendered_bodies[0]
    expected_commitment = privacy_request_commitment(rendered_body, _AuditKey())  # type: ignore[arg-type]
    assert receipt.request_commitment.commitment == expected_commitment
    assert receipt.request_commitment.algorithm == "hmac-sha256/yoetz-privacy-egress-request-v1"
    assert receipt.counts.request_body_bytes == len(rendered_body)
    # Provenance and the egress receipt agree about which policy authorized this dispatch, and
    # neither carries the placeholder the provider adapter would otherwise have minted.
    assert result.provenance.policy_digest == receipt.policy.policy_digest
    assert result.provenance.privacy_policy_digest == receipt.policy.policy_digest
    assert receipt.policy.policy_digest == policy.policy_digest
    assert result.provenance.policy_digest != "sha256:" + "0" * 64


def test_legacy_reconcile_never_constructs_external_provider() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    factory = _FakeExternalFactory(_script_factory)
    gateway = _gateway(audit=audit, clock=clock, external_factory=factory)
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)

    reconciliation = asyncio.run(
        gateway.reconcile_policy(effective, _human_authority(available=True))
    )

    assert reconciliation.activated_count == 0
    assert gateway.has_connected_provider_binding(_provider_binding()) is False


def test_a_placeholder_policy_digest_can_never_ride_a_successful_dispatch() -> None:
    """The dispatch-boundary fence, exercised directly at the boundary that owns it.

    Reaching this through the public dispatch path is impossible by construction -- the gateway
    already refuses to dispatch unless the case, the authorization, and the live registry agree on
    the policy digest, and a real policy digest is a canonical digest that is never all zeros. That
    is precisely why the fence is worth pinning: it is the assertion that keeps the pre-fix
    behaviour (an adapter-minted all-zero digest recorded as if a real policy had authorized it)
    from silently returning.
    """

    authorization = _authorization(
        authorization_id="aut_60000000-0000-4000-8000-000000000090",
        policy_digest=_DIGEST,
        service_generation=1,
    )
    case = _case(
        case_id="cas_60000000-0000-4000-8000-000000000091",
        authorization=authorization,
        payload=canonical_encode({"note": "hello"}),
    )
    zero = "sha256:" + "0" * 64
    judgment = SemanticJudgment("no_material_discrepancy", ())
    provenance = _provenance(SemanticStatus.SUCCEEDED, policy_digest=zero)

    # A real policy digest is bound through, replacing whatever the adapter asserted.
    bound = _with_policy_digest(SemanticResultSuccess(judgment, provenance), case)
    assert bound.provenance.policy_digest == _DIGEST
    assert bound.provenance.privacy_policy_digest == _DIGEST

    # A placeholder that survives the rebind is refused rather than recorded as audited.
    with pytest.raises(ValueError, match="privacy_gateway_provenance_policy_digest_placeholder"):
        _with_policy_digest(
            SemanticResultSuccess(judgment, provenance), replace(case, policy_digest=zero)
        )

    # A genuinely-blocked attempt that never reached a provider keeps its honest zeros.
    blocked = _with_policy_digest(
        SemanticResultUnavailable(
            _provenance(
                SemanticStatus.UNAVAILABLE,
                policy_digest=zero,
                failure_class=SemanticFailureClass.TRANSPORT,
            )
        ),
        replace(case, policy_digest=zero),
    )
    assert blocked.provenance.policy_digest == zero


def test_dispatch_rejects_authorization_case_mismatch() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    minter = _CredentialMinter()
    factory = _FakeExternalFactory(_script_factory)
    gateway = _gateway(audit=audit, clock=clock, credential_minter=minter, external_factory=factory)
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)

    async def run() -> tuple[SemanticResult, EgressAuthorization]:
        await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000020",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        payload = canonical_encode({"note": "hello"})
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000021",
            authorization=authorization,
            payload=payload,
        )
        mismatched = replace(case, authorization_id="aut_60000000-0000-4000-8000-000000000099")
        result = await gateway.dispatch_external_semantic(
            mismatched, authorization, _deadline(clock)
        )
        return result, authorization

    result, authorization = asyncio.run(run())

    assert type(result) is SemanticResultUnavailable
    assert minter.mint_calls == []
    assert factory.render_calls == 0
    assert audit.egress_receipts == []
    assert len(audit.decision_receipts) == 1
    _, receipt = audit.decision_receipts[0]
    assert receipt.outcome is PrivacyOutcome.APPROVAL_EXPIRED
    assert receipt.safe_failure_reason is PrivacyReason.AUTHORIZATION_REUSED
    assert receipt.dispatch_id is None
    assert receipt.authorization_id == authorization.authorization_id
    assert audit.authorization_state(authorization.authorization_id) == "authorized"


def test_repository_authority_revoked_before_render_has_zero_provider_side_effects() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    minter = _CredentialMinter()
    factory = _FakeExternalFactory(_script_factory)
    validations = 0

    async def revoked(_scope: object, _authority_digest: str) -> bool:
        nonlocal validations
        validations += 1
        return validations <= 2

    gateway = _gateway(
        audit=audit,
        clock=clock,
        credential_minter=minter,
        external_factory=factory,
        repository_authority_validator=revoked,
    )
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)

    async def run() -> tuple[SemanticResult, EgressAuthorization]:
        await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000023",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000024",
            authorization=authorization,
            payload=canonical_encode({"note": "hello"}),
        )
        return (
            await gateway.dispatch_external_semantic(case, authorization, _deadline(clock)),
            authorization,
        )

    result, authorization = asyncio.run(run())
    assert type(result) is SemanticResultUnavailable
    assert validations == 3
    assert factory.render_calls == 0
    assert factory.built == []
    assert minter.mint_calls == []
    assert audit.authorization_state(authorization.authorization_id) == "authorized"


def test_repository_authority_rechecked_after_render_before_credential_mint() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    minter = _CredentialMinter()
    factory = _FakeExternalFactory(_script_factory)
    validations = 0

    async def revoke_after_render(_scope: object, _authority_digest: str) -> bool:
        nonlocal validations
        validations += 1
        return validations <= 3

    gateway = _gateway(
        audit=audit,
        clock=clock,
        credential_minter=minter,
        external_factory=factory,
        repository_authority_validator=revoke_after_render,
    )
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)

    async def run() -> tuple[SemanticResult, EgressAuthorization]:
        await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000025",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000026",
            authorization=authorization,
            payload=canonical_encode({"note": "hello"}),
        )
        return (
            await gateway.dispatch_external_semantic(case, authorization, _deadline(clock)),
            authorization,
        )

    result, authorization = asyncio.run(run())
    assert type(result) is SemanticResultUnavailable
    assert validations == 4
    assert factory.render_calls == 1
    assert factory.built == []
    assert minter.mint_calls == []
    assert audit.authorization_state(authorization.authorization_id) == "authorized"


def test_repository_revocation_during_build_admission_never_invokes_factory_builder() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    factory = _FakeExternalFactory(_script_factory)
    validations = 0
    build_calls = 0
    holder: dict[str, PolicyEnforcingOutboundGateway] = {}

    async def revoke_at_build_boundary(_scope: object, _authority_digest: str) -> bool:
        nonlocal validations
        validations += 1
        if validations == 2:
            await holder["gateway"].close_revoked(1)
        return True

    def build_factory() -> _FakeExternalFactory:
        nonlocal build_calls
        build_calls += 1
        return factory

    gateway = _gateway(
        audit=audit,
        clock=clock,
        external_factory_builder=build_factory,
        repository_authority_validator=revoke_at_build_boundary,
    )
    holder["gateway"] = gateway
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)

    reconciliation = asyncio.run(
        _reconcile_repository(gateway, effective, _human_authority(available=True))
    )

    assert validations == 2
    assert build_calls == 0
    assert reconciliation.activated_count == 0
    assert gateway.has_connected_provider_binding(_provider_binding()) is False


def test_repository_revocation_inside_final_validator_wins_before_consume() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    minter = _CredentialMinter()
    factory = _FakeExternalFactory(_script_factory)
    validations = 0
    holder: dict[str, PolicyEnforcingOutboundGateway] = {}

    async def revoke_at_final_boundary(_scope: object, _authority_digest: str) -> bool:
        nonlocal validations
        validations += 1
        # Two validations admit reconciliation; dispatch then validates before render, before
        # mint, and finally at the consume boundary.
        if validations == 5:
            await holder["gateway"].close_revoked(1)
        return True

    gateway = _gateway(
        audit=audit,
        clock=clock,
        credential_minter=minter,
        external_factory=factory,
        repository_authority_validator=revoke_at_final_boundary,
    )
    holder["gateway"] = gateway
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)

    async def run() -> tuple[SemanticResult, EgressAuthorization]:
        await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000027",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000028",
            authorization=authorization,
            payload=canonical_encode({"note": "hello"}),
        )
        return (
            await gateway.dispatch_external_semantic(case, authorization, _deadline(clock)),
            authorization,
        )

    result, authorization = asyncio.run(run())
    assert type(result) is SemanticResultUnavailable
    assert validations == 5
    assert len(minter.mint_calls) == 1
    assert len(factory.built) == 1
    assert factory.built[0].evaluate_calls == 0
    assert audit.authorization_state(authorization.authorization_id) == "authorized"


def test_revocation_after_consume_waits_for_admitted_attempt_boundary() -> None:
    clock = _Clock()
    consume_entered = asyncio.Event()
    allow_consume = asyncio.Event()

    class _BlockingAudit(_FullPrivacyAudit):
        async def consume(
            self, authorization_id: str, dispatch_id: str, now: datetime
        ) -> ConsumedAuthorization:
            consume_entered.set()
            await allow_consume.wait()
            return await super().consume(authorization_id, dispatch_id, now)

    audit = _BlockingAudit()
    factory = _FakeExternalFactory(_script_factory)
    gateway = _gateway(audit=audit, clock=clock, external_factory=factory)
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)

    async def run() -> tuple[SemanticResult, EgressAuthorization, bool]:
        await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000029",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000030",
            authorization=authorization,
            payload=canonical_encode({"note": "hello"}),
        )
        dispatch = asyncio.create_task(
            gateway.dispatch_external_semantic(case, authorization, _deadline(clock))
        )
        await asyncio.wait_for(consume_entered.wait(), timeout=1)
        revoke = asyncio.create_task(gateway.close_revoked(1))
        await asyncio.sleep(0)
        revoke_was_blocked = not revoke.done()
        allow_consume.set()
        result = await dispatch
        await revoke
        return result, authorization, revoke_was_blocked

    result, authorization, revoke_was_blocked = asyncio.run(run())
    assert revoke_was_blocked is True
    assert type(result) is SemanticResultSuccess
    assert factory.built[0].evaluate_calls == 1
    assert audit.authorization_state(authorization.authorization_id) == "consumed"


def test_authority_mutation_fence_blocks_old_activation_and_consume_through_commit() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    factory = _FakeExternalFactory(_script_factory)
    final_validation_entered = asyncio.Event()
    allow_final_validation = asyncio.Event()
    mutation_entered = asyncio.Event()
    allow_commit = asyncio.Event()
    authority_current = True
    validations = 0
    build_calls = 0

    async def validate(_scope: object, _authority_digest: str) -> bool:
        nonlocal validations
        validations += 1
        if validations == 5:
            final_validation_entered.set()
            await allow_final_validation.wait()
        return authority_current

    def build_factory() -> _FakeExternalFactory:
        nonlocal build_calls
        build_calls += 1
        return factory

    gateway = _gateway(
        audit=audit,
        clock=clock,
        external_factory_builder=build_factory,
        repository_authority_validator=validate,
    )
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)

    async def run() -> tuple[SemanticResult, EgressAuthorization, ProviderReconciliation, bool]:
        nonlocal authority_current
        await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000031",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000032",
            authorization=authorization,
            payload=canonical_encode({"note": "hello"}),
        )
        dispatch = asyncio.create_task(
            gateway.dispatch_external_semantic(case, authorization, _deadline(clock))
        )
        await asyncio.wait_for(final_validation_entered.wait(), timeout=1)

        async def mutate_authority() -> None:
            nonlocal authority_current
            async with gateway.authority_mutation_fence():
                mutation_entered.set()
                await allow_commit.wait()
                authority_current = False

        mutation = asyncio.create_task(mutate_authority())
        await asyncio.wait_for(mutation_entered.wait(), timeout=1)
        activation = asyncio.create_task(_reconcile_repository(gateway, effective, human))
        allow_final_validation.set()
        await asyncio.sleep(0)
        both_blocked_during_commit = not dispatch.done() and not activation.done()
        allow_commit.set()
        result, reconciliation = await asyncio.gather(dispatch, activation)
        await mutation
        return result, authorization, reconciliation, both_blocked_during_commit

    result, authorization, reconciliation, both_blocked = asyncio.run(run())
    assert both_blocked is True
    assert type(result) is SemanticResultUnavailable
    assert audit.authorization_state(authorization.authorization_id) == "authorized"
    assert reconciliation.activated_count == 0
    assert build_calls == 1
    assert len(factory.built) == 1
    assert factory.built[0].evaluate_calls == 0


def test_final_body_scan_blocks_before_credential_mint() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    minter = _CredentialMinter()
    factory = _ForbiddenBodyFactory(_script_factory)
    gateway = _gateway(audit=audit, clock=clock, credential_minter=minter, external_factory=factory)
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)

    async def run() -> tuple[SemanticResult, EgressAuthorization]:
        await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000030",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        payload = canonical_encode({"note": "hello"})
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000031",
            authorization=authorization,
            payload=payload,
        )
        result = await gateway.dispatch_external_semantic(case, authorization, _deadline(clock))
        return result, authorization

    result, authorization = asyncio.run(run())

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.failure_class is SemanticFailureClass.RESPONSE_CONTENT
    assert minter.mint_calls == []  # never reached credential minting
    assert factory.render_calls == 1
    assert audit.egress_receipts == []
    assert len(audit.decision_receipts) == 1
    _, receipt = audit.decision_receipts[0]
    assert receipt.outcome is PrivacyOutcome.BLOCKED_FORBIDDEN_DATA
    assert receipt.safe_failure_reason is PrivacyReason.NEVER_SEND_DETECTED
    assert receipt.authorization_id is None  # one of the 5 outcomes that never binds an authority
    assert receipt.dispatch_id is None
    assert receipt.consent_source is ConsentSource.NONE
    assert audit.authorization_state(authorization.authorization_id) == "authorized"


def test_final_body_scan_keeps_generic_dotted_assignment_blocked() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    minter = _CredentialMinter()
    factory = _HeuristicBodyFactory(_script_factory)
    gateway = _gateway(audit=audit, clock=clock, credential_minter=minter, external_factory=factory)
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)

    async def run() -> SemanticResult:
        await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000032",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        payload = canonical_encode({"note": "hello"})
        return await gateway.dispatch_external_semantic(
            _case(
                case_id="cas_60000000-0000-4000-8000-000000000033",
                authorization=authorization,
                payload=payload,
            ),
            authorization,
            _deadline(clock),
        )

    result = asyncio.run(run())

    assert type(result) is SemanticResultUnavailable
    assert result.provenance.failure_class is SemanticFailureClass.RESPONSE_CONTENT
    assert minter.mint_calls == []
    assert factory.render_calls == 1
    assert audit.egress_receipts == []
    assert len(audit.decision_receipts) == 1
    _, receipt = audit.decision_receipts[0]
    assert receipt.outcome is PrivacyOutcome.BLOCKED_FORBIDDEN_DATA
    assert receipt.safe_failure_reason is PrivacyReason.NEVER_SEND_DETECTED


def test_expired_authorization_is_rejected_before_dispatch() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    factory = _FakeExternalFactory(_script_factory)
    gateway = _gateway(audit=audit, clock=clock, external_factory=factory)
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)

    async def run() -> SemanticResult:
        await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000040",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
            expires_at=_NOW - timedelta(seconds=1),
        )
        audit.seed_authorized(authorization)
        payload = canonical_encode({"note": "hello"})
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000041",
            authorization=authorization,
            payload=payload,
        )
        return await gateway.dispatch_external_semantic(case, authorization, _deadline(clock))

    asyncio.run(run())

    assert factory.render_calls == 0
    assert len(audit.decision_receipts) == 1
    _, receipt = audit.decision_receipts[0]
    assert receipt.outcome is PrivacyOutcome.APPROVAL_EXPIRED
    assert receipt.safe_failure_reason is PrivacyReason.AUTHORIZATION_EXPIRED


def test_expired_deadline_is_rejected_before_dispatch() -> None:
    clock = _Clock(monotonic=100.0)
    audit = _FullPrivacyAudit()
    factory = _FakeExternalFactory(_script_factory)
    gateway = _gateway(audit=audit, clock=clock, external_factory=factory)
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)

    async def run() -> SemanticResult:
        await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000042",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        payload = canonical_encode({"note": "hello"})
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000043",
            authorization=authorization,
            payload=payload,
        )
        already_expired = Deadline(_NOW + timedelta(minutes=5), clock.monotonic - 1.0)
        return await gateway.dispatch_external_semantic(case, authorization, already_expired)

    asyncio.run(run())

    assert factory.render_calls == 0
    assert len(audit.decision_receipts) == 1
    _, receipt = audit.decision_receipts[0]
    assert receipt.outcome is PrivacyOutcome.TIMEOUT
    assert receipt.safe_failure_reason is PrivacyReason.DEADLINE_EXPIRED


def test_preconsume_refusal_records_the_closed_reason_as_owner_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pre-dispatch refusal is publicly `unavailable`; the owner diagnostic names the reason."""

    import yoetz.adapters.privacy.gateway as gateway_module

    recorded: list[dict[str, object]] = []

    def capture(**kwargs: object) -> str:
        recorded.append(dict(kwargs))
        return "err_00000000-0000-4000-8000-000000000001"

    monkeypatch.setattr(gateway_module, "record_bounded_event_without_raising", capture)
    clock = _Clock()
    audit = _FullPrivacyAudit()
    factory = _FakeExternalFactory(_script_factory)
    gateway = _gateway(audit=audit, clock=clock, external_factory=factory)
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=False)

    async def run() -> SemanticResult:
        await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000060",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000061",
            authorization=authorization,
            payload=canonical_encode({"note": "hello"}),
        )
        return await gateway.dispatch_external_semantic(case, authorization, _deadline(clock))

    result = asyncio.run(run())

    assert type(result) is SemanticResultUnavailable
    assert recorded == [
        {
            "component": "privacy_gateway",
            "operation": "egress_preconsume",
            "reason": PrivacyReason.CHANNEL_UNAVAILABLE.value,
            "request_id": _REQUEST,
        }
    ]


def test_human_authority_unavailable_empties_external_registry() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    factory = _FakeExternalFactory(_script_factory)
    gateway = _gateway(audit=audit, clock=clock, external_factory=factory)
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=False)

    async def run() -> tuple[ProviderReconciliation, SemanticResult]:
        reconciliation = await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000050",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        payload = canonical_encode({"note": "hello"})
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000051",
            authorization=authorization,
            payload=payload,
        )
        result = await gateway.dispatch_external_semantic(case, authorization, _deadline(clock))
        return reconciliation, result

    reconciliation, result = asyncio.run(run())

    assert reconciliation.activated_count == 0
    assert type(result) is SemanticResultUnavailable
    assert factory.render_calls == 0
    assert len(audit.decision_receipts) == 1
    _, receipt = audit.decision_receipts[0]
    assert receipt.outcome is PrivacyOutcome.CHANNEL_UNAVAILABLE
    assert receipt.authorization_id is None


def test_policy_tightening_closes_registry_and_denies_further_dispatch() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    factory = _FakeExternalFactory(_script_factory)
    gateway = _gateway(audit=audit, clock=clock, external_factory=factory)
    wide = _policy(external_enabled=True, local_enabled=False)
    wide_effective = EffectivePrivacyPolicy(wide, 1, wide.policy_digest)
    tight = _policy(external_enabled=False, local_enabled=False, version=2, digest=_DIGEST_2)
    tight_effective = EffectivePrivacyPolicy(tight, 2, tight.policy_digest)
    human = _human_authority(available=True)

    async def run() -> tuple[SemanticResult, ProviderReconciliation, SemanticResult]:
        await _reconcile_repository(gateway, wide_effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000060",
            policy_digest=wide.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        payload = canonical_encode({"note": "hello"})
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000061",
            authorization=authorization,
            payload=payload,
        )
        first = await gateway.dispatch_external_semantic(case, authorization, _deadline(clock))

        second_reconciliation = await _reconcile_repository(gateway, tight_effective, human)

        stale_authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000062",
            policy_digest=wide.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(stale_authorization)
        stale_case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000063",
            authorization=stale_authorization,
            payload=payload,
        )
        second = await gateway.dispatch_external_semantic(
            stale_case, stale_authorization, _deadline(clock)
        )
        return first, second_reconciliation, second

    first, second_reconciliation, second = asyncio.run(run())

    assert type(first) is SemanticResultSuccess
    assert second_reconciliation.deactivated_count == 1
    assert factory.closed is True
    assert type(second) is SemanticResultUnavailable
    assert factory.render_calls == 1  # the tightened attempt never rendered a second body


def test_close_is_idempotent_and_fences_new_work() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    factory = _FakeExternalFactory(_script_factory)
    gateway = _gateway(audit=audit, clock=clock, external_factory=factory)
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)

    async def run() -> tuple[ProviderReconciliation, SemanticResult]:
        await _reconcile_repository(gateway, effective, human)
        await asyncio.gather(gateway.close(), gateway.close())

        reconciliation = await _reconcile_repository(gateway, effective, human)

        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000070",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        payload = canonical_encode({"note": "hello"})
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000071",
            authorization=authorization,
            payload=payload,
        )
        result = await gateway.dispatch_external_semantic(case, authorization, _deadline(clock))
        return reconciliation, result

    reconciliation, result = asyncio.run(run())

    assert factory.closed is True
    assert reconciliation == ProviderReconciliation(1, 0, 0, ())
    assert type(result) is SemanticResultUnavailable
    assert factory.render_calls == 0  # close fences new work before any adapter I/O


def test_local_model_dispatch_consumes_reservation_and_calls_evaluator_once() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    binding = _local_binding()
    profile = LocalModelEndpointProfile(
        profile_id="local-profile",
        profile_version="1.0.0",
        endpoint_profile_id=binding.endpoint_profile_id,
        endpoint_profile_version=binding.endpoint_profile_version,
        model=binding.model_id,
        protocol_version="1.0.0",
        judgment_schema_version="1.0.0",
        timeout_seconds=30,
        expected_service_identity="local-svc",
        expected_owner_uid=0,
        expected_peer_uid=0,
        expected_socket_mode=0o600,
        release_resource_digest=_DIGEST,
        capability_evidence_digest=_DIGEST,
    )
    local_registry = InstalledLocalModelProfileRegistry((profile,))
    handle = _LocalSocketHandle(
        1,
        _DIGEST,
        canonical_encode(
            {
                "conclusion": "no_material_discrepancy",
                "review_summary": "No review summary recorded.",
                "verified": [],
                "reviewer_challenges": [],
                "prior_finding_verdicts": [],
            }
        ),
    )
    resolver = _LocalResolver(handle)
    gateway = _gateway(
        audit=audit, clock=clock, local_registry=local_registry, local_resolver=resolver
    )
    policy = _policy(external_enabled=False, local_enabled=True)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)

    async def run() -> tuple[ProviderReconciliation, SemanticResult]:
        reconciliation = await _reconcile_repository(gateway, effective, human)
        audit.seed_local_reserved(_PROPOSAL)
        payload = canonical_encode({"note": "hello"})
        case = ApprovedLocalDisclosureCase(
            case_id="cas_60000000-0000-4000-8000-000000000080",
            request_id=_REQUEST,
            privacy_proposal_id=_PROPOSAL,
            payload=payload,
            media_type="application/json",
            included_item_ids=("item-1",),
            approved_categories=(DataCategory.TASK_DESCRIPTION,),
            blocked_categories=(),
            byte_count=len(payload),
            token_count=8,
            sink=LocalDisclosureSink.LOCAL_MODEL,
            binding=binding,
            purpose="local-check",
            policy_digest=policy.policy_digest,
            case_digest=_DIGEST,
        )
        result = await gateway.dispatch_local_semantic(case, _deadline(clock))
        return reconciliation, result

    reconciliation, result = asyncio.run(run())

    assert reconciliation.activated_count == 1
    assert type(result) is SemanticResultSuccess
    assert resolver.resolve_calls == 1
    assert len(handle.sent) == 1
    assert audit.consume_local_calls == [(_PROPOSAL, _DIGEST)]


def test_evaluator_exception_yields_transport_failed_without_reusable_authorization() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    minter = _CredentialMinter()
    factory = _RaisingEvaluatorFactory(_script_factory)
    gateway = _gateway(audit=audit, clock=clock, credential_minter=minter, external_factory=factory)
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)

    async def run() -> tuple[SemanticResult, SemanticResult]:
        await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000090",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        payload = canonical_encode({"note": "hello"})
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000091",
            authorization=authorization,
            payload=payload,
        )
        deadline = _deadline(clock)
        first = await gateway.dispatch_external_semantic(case, authorization, deadline)
        # A retry with the exact same (now-consumed) authorization must be denied: the gateway
        # never accepts an already-consumed authority as proof of permission.
        second = await gateway.dispatch_external_semantic(case, authorization, deadline)
        return first, second

    first, second = asyncio.run(run())

    assert type(first) is SemanticResultUnavailable
    assert first.provenance.failure_class is SemanticFailureClass.TRANSPORT
    assert "10.0.0.7" not in repr(first)
    assert "native-provider-socket-reset" not in repr(first)
    assert len(audit.egress_receipts) == 1
    _, attempt_receipt = audit.egress_receipts[0]
    assert attempt_receipt.outcome is PrivacyOutcome.TRANSPORT_FAILED
    assert attempt_receipt.safe_failure_reason is PrivacyReason.OUTCOME_UNKNOWN

    assert type(second) is SemanticResultUnavailable
    assert len(audit.egress_receipts) == 1  # no second physical attempt was ever admitted
    assert len(audit.decision_receipts) == 1
    _, retry_receipt = audit.decision_receipts[0]
    assert retry_receipt.outcome is PrivacyOutcome.APPROVAL_EXPIRED
    assert retry_receipt.safe_failure_reason is PrivacyReason.AUTHORIZATION_REUSED
    # A fresh credential handle is minted for each attempt (never reused across dispatches), even
    # though the second attempt's transport is never actually invoked.
    assert len(minter.mint_calls) == 2
    assert factory.built == []  # the raising factory never registers a built evaluator list


def test_cancelled_admitted_attempt_still_records_its_outcome_unknown_receipt() -> None:
    """A consumed authorization owes exactly one terminal receipt, cancellation included (#755).

    A foreground runtime rebind cancels the in-flight advisory attempt after the consume CAS.
    ``asyncio.CancelledError`` is a ``BaseException``: before this fix it skipped the receipt
    entirely and left the audit row ``receipt_pending`` with no recovery path. The gateway now
    parks the owed ``outcome_unknown`` receipt before the provider call and records it through a
    shielded write, then lets cancellation propagate so the rebind is not held open.
    """

    clock = _Clock()
    audit = _FullPrivacyAudit()
    minter = _CredentialMinter()
    factory = _CancellingEvaluatorFactory(_script_factory)
    gateway = _gateway(audit=audit, clock=clock, credential_minter=minter, external_factory=factory)
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)

    async def run() -> EgressAuthorization:
        await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000097",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000098",
            authorization=authorization,
            payload=canonical_encode({"note": "hello"}),
        )
        with pytest.raises(asyncio.CancelledError):
            await gateway.dispatch_external_semantic(case, authorization, _deadline(clock))
        return authorization

    authorization = asyncio.run(run())

    assert audit.authorization_state(authorization.authorization_id) == "consumed"
    # Exactly one terminal receipt, and it is honest about the unknown provider outcome.
    assert len(audit.egress_receipts) == 1
    dispatch_id, receipt = audit.egress_receipts[0]
    assert receipt.outcome is PrivacyOutcome.TRANSPORT_FAILED
    assert receipt.safe_failure_reason is PrivacyReason.OUTCOME_UNKNOWN
    assert receipt.dispatch_id == dispatch_id
    assert receipt.authorization_id == authorization.authorization_id
    assert receipt.request_commitment is not None
    # The same receipt was parked as durable recovery material before the provider call, so a
    # crash in that window is reconcilable rather than stranded.
    assert len(audit.parked_receipts) == 1
    assert audit.parked_receipts[0] == (dispatch_id, receipt)
    assert len(minter.mint_calls) == 1


def test_external_runtime_authority_never_mints_a_vault_credential_and_records_unknown() -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    minter = _CredentialMinter()
    runtime_evidence = RuntimeAttemptEvidence(
        credential_authority="external_runtime_oauth",
        runtime_version="0.150.1",
        runtime_source_identity="openai-codex-npm-darwin-arm64-0.150.1",
        executable_sha256=_DIGEST,
        app_server_schema_sha256=_DIGEST,
        capability_cell_sha256=_DIGEST,
        capability_profile="codex-evaluator/0.150.1/v1",
        capability_evidence_expires_at="2026-11-30T00:00:00Z",
        launcher_sha256=_DIGEST,
        isolated_config_sha256=_DIGEST,
        disclosed_case_sha256=_DIGEST,
        instruction_sha256=_DIGEST,
        output_schema_sha256=_DIGEST,
        selection_sha256=_DIGEST,
        upstream_body_observability="unavailable",
        auth_mode="chatgpt",
        plan_type="plus",
        reasoning_effort="high",
        thread_id="019a0000-0000-7000-8000-000000000001",
        turn_id="019a0000-0000-7000-8000-000000000002",
        final_output_sha256=None,
        case_disclosed=True,
        turn_acknowledged=True,
        process_cleanup="terminated",
    )

    class RuntimeFactory:
        credential_authority = "external_runtime_oauth"

        def render(self, case: ApprovedOutboundCase) -> bytes:
            return case.payload

        def build_evaluator(
            self, binding: object, credential: object, request_commitment: object
        ) -> object:
            del binding, request_commitment
            assert type(credential) is ExternalRuntimeAuthority

            class Evaluator:
                async def evaluate(self, case: object, deadline: object) -> SemanticResult:
                    del case, deadline
                    return SemanticResultUnavailable(
                        replace(
                            _provenance(
                                SemanticStatus.UNAVAILABLE,
                                policy_digest=_DIGEST,
                                failure_class=SemanticFailureClass.TRANSPORT,
                            ),
                            runtime_evidence=runtime_evidence,
                        )
                    )

            return Evaluator()

    gateway = _gateway(
        audit=audit,
        clock=clock,
        credential_minter=minter,
        external_factory=RuntimeFactory(),
    )
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)

    async def run() -> SemanticResult:
        await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000092",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        payload = canonical_encode({"note": "hello"})
        return await gateway.dispatch_external_semantic(
            _case(
                case_id="cas_60000000-0000-4000-8000-000000000093",
                authorization=authorization,
                payload=payload,
            ),
            authorization,
            _deadline(clock),
        )

    result = asyncio.run(run())

    assert type(result) is SemanticResultUnavailable
    assert minter.mint_calls == []
    assert len(audit.egress_receipts) == 1
    _, receipt = audit.egress_receipts[0]
    assert receipt.outcome is PrivacyOutcome.TRANSPORT_FAILED
    assert receipt.safe_failure_reason is PrivacyReason.OUTCOME_UNKNOWN
    assert receipt.counts.request_body_bytes is not None
    assert receipt.counts.request_body_bytes > 0


def test_bundled_chat_completions_binding_reconciles_without_factory_unavailable() -> None:
    """A configured preset must become a live factory, not an unavailable-binding reconciliation.

    `factory_unavailable` is invisible to the caller: the check still returns, the AI-powered review
    simply never happened. Asserting the real dispatch table against the real policy binding is the
    only place the config-to-gateway key agreement is proven.
    """

    clock = _Clock()
    audit = _FullPrivacyAudit()
    provider = anthropic_provider(model="claude-sonnet-4-6")
    builders = external_factory_builders_from_config(provider, clock=clock)  # type: ignore[arg-type]
    binding = provider_binding_from_config(provider)
    gateway = PolicyEnforcingOutboundGateway(
        external_factory_builders=builders,  # type: ignore[arg-type]
        local_model_registry=InstalledLocalModelProfileRegistry(),
        local_model_resolver=None,
        credential_minter=_CredentialMinter(),  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        classifier=LocalPrivacyEnforcer(),
        audit_mac=_AuditKey(),  # type: ignore[arg-type]
        clock=clock,  # type: ignore[arg-type]
        ids=_Ids(),  # type: ignore[arg-type]
        repository_authority_validator=_repository_authority_current,  # type: ignore[arg-type]
    )
    policy = _policy(external_enabled=True, local_enabled=False, binding=binding)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)

    async def run() -> ProviderReconciliation:
        reconciliation = await _reconcile_repository(
            gateway, effective, _human_authority(available=True)
        )
        await gateway.close()
        return reconciliation

    reconciliation = asyncio.run(run())

    assert reconciliation.unavailable_bindings == ()
    assert reconciliation.activated_count == 1


def test_unregistered_endpoint_profile_reports_factory_unavailable_not_a_silent_pass() -> None:
    """The honest failure for an unbuildable binding stays a reported unavailable reconciliation."""

    clock = _Clock()
    audit = _FullPrivacyAudit()
    gateway = PolicyEnforcingOutboundGateway(
        external_factory_builders={},
        local_model_registry=InstalledLocalModelProfileRegistry(),
        local_model_resolver=None,
        credential_minter=_CredentialMinter(),  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        classifier=LocalPrivacyEnforcer(),
        audit_mac=_AuditKey(),  # type: ignore[arg-type]
        clock=clock,  # type: ignore[arg-type]
        ids=_Ids(),  # type: ignore[arg-type]
        repository_authority_validator=_repository_authority_current,  # type: ignore[arg-type]
    )
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)

    async def run() -> ProviderReconciliation:
        reconciliation = await _reconcile_repository(
            gateway, effective, _human_authority(available=True)
        )
        await gateway.close()
        return reconciliation

    reconciliation = asyncio.run(run())

    assert reconciliation.activated_count == 0
    assert [reason for _digest, reason in reconciliation.unavailable_bindings] == [
        "factory_unavailable"
    ]


@pytest.mark.parametrize("phase", ["parking", "parking_failure", "provider", "receipt"])
@pytest.mark.parametrize("clock_delta", [30, -30])
def test_cancellation_at_each_admitted_await_terminalizes_without_redispatch(
    phase: str, clock_delta: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = _Clock()
    audit = _FullPrivacyAudit()
    factory = _FakeExternalFactory(_script_factory)
    gateway = _gateway(audit=audit, clock=clock, external_factory=factory)
    policy = _policy(external_enabled=True, local_enabled=False)
    effective = EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
    human = _human_authority(available=True)
    entered = asyncio.Event()
    first = True

    async def pause_once() -> None:
        nonlocal first
        if first:
            first = False
            entered.set()
            await asyncio.Event().wait()

    park = audit.park_attempt_reconciliation
    complete = audit.complete_egress
    build = factory.build_evaluator

    async def parking(dispatch_id: str, receipt: EgressReceipt) -> None:
        if phase == "parking_failure":
            raise RuntimeError("reconciliation_store_unavailable")
        if phase == "parking":
            await pause_once()
        await park(dispatch_id, receipt)

    async def completing(dispatch_id: str, receipt: EgressReceipt) -> None:
        if phase == "receipt":
            await pause_once()
        await complete(dispatch_id, receipt)

    def building(binding: object, credential: object, request_commitment: object) -> object:
        evaluator = build(binding, credential, request_commitment)
        assert isinstance(evaluator, _FakeEvaluator)
        evaluate = evaluator.evaluate

        async def evaluating(case: object, deadline: object) -> object:
            if phase == "provider":
                await pause_once()
            return await evaluate(case, deadline)

        monkeypatch.setattr(evaluator, "evaluate", evaluating)
        return evaluator

    monkeypatch.setattr(audit, "park_attempt_reconciliation", parking)
    monkeypatch.setattr(audit, "complete_egress", completing)
    monkeypatch.setattr(factory, "build_evaluator", building)

    async def run() -> None:
        await _reconcile_repository(gateway, effective, human)
        authorization = _authorization(
            authorization_id="aut_60000000-0000-4000-8000-000000000097",
            policy_digest=policy.policy_digest,
            service_generation=human.service_generation,
        )
        audit.seed_authorized(authorization)
        case = _case(
            case_id="cas_60000000-0000-4000-8000-000000000098",
            authorization=authorization,
            payload=canonical_encode({"note": "hello"}),
        )
        pending = asyncio.create_task(
            gateway.dispatch_external_semantic(case, authorization, _deadline(clock))
        )
        if phase == "parking_failure":
            with pytest.raises(RuntimeError, match="reconciliation_store_unavailable"):
                await asyncio.wait_for(pending, 5)
        else:
            await asyncio.wait_for(entered.wait(), 5)
            clock.utc += timedelta(seconds=clock_delta)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(pending, 5)
        assert audit.authorization_state(authorization.authorization_id) == "consumed"

    asyncio.run(run())
    assert len(audit.egress_receipts) == 1
    receipt = audit.egress_receipts[0][1]
    if phase != "receipt":
        assert receipt.outcome is PrivacyOutcome.TRANSPORT_FAILED
        assert receipt.safe_failure_reason is PrivacyReason.OUTCOME_UNKNOWN
        expected_finished_at = (
            _NOW if phase == "parking_failure" else _NOW + timedelta(seconds=max(0, clock_delta))
        )
        assert receipt.finished_at == expected_finished_at
    else:
        # The provider result already existed; cancellation preserves it instead of replacing it.
        assert receipt.outcome is not PrivacyOutcome.TRANSPORT_FAILED
    assert sum(item.evaluate_calls for item in factory.built) <= (
        0 if phase == "parking_failure" else 1
    )
