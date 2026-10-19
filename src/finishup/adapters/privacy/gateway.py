"""The sole authorization-fenced outbound and local-model AI-powered review gateway.

``PolicyEnforcingOutboundGateway`` is the only component permitted to own AI-powered review provider
transports. It revalidates and atomically consumes privacy authority immediately before dispatch,
renders and scans the exact final application request body before any credential is minted, and
never exposes a provider client, credential, or raw response to application code. ``ProviderRegistry``
is an immutable, generation-fenced snapshot of currently permitted adapters; only ``reconcile_policy``
may swap it, and only after policy/vault/human-authority validation.

Two narrow seams decouple this file from provider-specific SDK wiring (kept in
``adapters/providers/*`` and daemon composition, both outside this file's ownership):

- ``ExternalProviderFactory`` is a credential-free, per-``ProviderBinding`` factory that
  deterministically renders the final request body from an ``ApprovedOutboundCase`` (no I/O), and
  builds a one-attempt ``SemanticEvaluatorPort`` bound to a fresh credential handle. Daemon
  composition is expected to supply one factory builder per exact external binding (for example one
  wrapping ``adapters/providers/openai_responses.py``'s ``render_case``/``OpenAIResponsesEvaluator``).
- ``ProviderCredentialMinter`` is the narrow service-vault boundary that mints exactly one
  ``ProviderCredentialHandle`` per ``ProviderAttemptAuthBinding``; it never resolves generic secrets.

Local-model dispatch does not go through either seam: ``reconcile_policy`` alone may ask the
supplied ``LocalModelSocketResolverPort`` for a socket handle (only after the durable policy proves
``local_model_enabled`` for the exact installed profile), and the resulting
``LocalModelEvaluator`` is materialized once per reconciliation and reused directly at dispatch.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from datetime import datetime
from types import MappingProxyType
from typing import Protocol

from finishup.adapters.privacy.catalog import _scope_digest  # pyright: ignore[reportPrivateUsage]
from finishup.adapters.privacy.local_enforcer import SecretScanRuleset
from finishup.adapters.providers.local_model import (
    InstalledLocalModelProfileRegistry,
    LocalModelEvaluator,
    LocalModelSocketResolverPort,
)
from finishup.adapters.providers.reviewer_reply import REVIEWER_REPLY_SCHEMAS
from finishup.domain.findings import SamplingParams, SemanticFailureClass
from finishup.domain.privacy import (
    PRIVACY_REQUEST_COMMITMENT_ALGORITHM,
    ApprovedLocalDisclosureCase,
    ApprovedOutboundCase,
    ApprovedProviderCase,
    AuthorizationScope,
    ConsentSource,
    CredentialHeuristic,
    EgressAuthorization,
    EgressChannel,
    EgressReceipt,
    ForbiddenDataKind,
    LocalDisclosureSink,
    PrivacyOutcome,
    PrivacyPolicy,
    PrivacyReason,
    ProviderBinding,
    ProviderDataUseProfile,
    ReceiptCounts,
    ReceiptPolicyBinding,
    ReceiptSecretScan,
    ReceiptSecretScanStage,
    ReceiptTransformations,
    RequestCommitment,
    egress_origin_operation,
)
from finishup.domain.values import validate_commitment, validate_sha256_digest
from finishup.observability.logging import (
    record_bounded_event_without_raising,
    record_classified_exception_without_raising,
)
from finishup.observability.privacy import privacy_request_commitment
from finishup.observability.semantic_context import report_semantic_progress
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.keys import MacKeyHandle
from finishup.ports.privacy import (
    EffectivePrivacyPolicy,
    HumanAuthorityCapability,
    OutboundGatewayPort,
    PrivacyAuditPort,
    PrivacyClassifierPort,
    ProviderReconciliation,
)
from finishup.ports.secret_memory import ProviderAttemptAuthBinding, ProviderCredentialHandle
from finishup.ports.semantic import (
    Deadline,
    ExternalRuntimeAuthority,
    ProviderAttemptProvenance,
    SemanticEvaluatorPort,
    SemanticResult,
    SemanticResultInvalid,
    SemanticResultLate,
    SemanticResultRefused,
    SemanticResultReply,
    SemanticResultSuccess,
    SemanticResultTimeout,
    SemanticResultUnavailable,
)
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.ids import IdKind
from finishup.protocol.models import SemanticProgressPhase, SemanticStatus

__all__ = [
    "ExternalProviderFactory",
    "PolicyEnforcingOutboundGateway",
    "ProviderCredentialMinter",
    "ProviderRegistry",
]

_ZERO_DIGEST = "sha256:" + "0" * 64
_SCAN = SecretScanRuleset()


def _final_scan(
    classifier: PrivacyClassifierPort, data: bytes, credential_heuristic: CredentialHeuristic
) -> tuple[ForbiddenDataKind, ...]:
    """Run the final exact-byte scan under the setting the case was prepared with (#982).

    The default keeps the historical call shape; only an owner opt-out names the setting.
    """

    if credential_heuristic is CredentialHeuristic.ENFORCED:
        return classifier.scan_exact_bytes(data)
    return classifier.scan_exact_bytes(data, credential_heuristic=credential_heuristic)


_NO_AUTHORIZATION_ID_OUTCOMES = frozenset(
    {
        PrivacyOutcome.BLOCKED_BY_POLICY,
        PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
        PrivacyOutcome.CLASSIFICATION_UNCERTAIN,
        PrivacyOutcome.HUMAN_DENIED,
        PrivacyOutcome.CHANNEL_UNAVAILABLE,
    }
)

_PRECONSUME_OUTCOME: Mapping[PrivacyReason, PrivacyOutcome] = MappingProxyType(
    {
        PrivacyReason.CHANNEL_UNAVAILABLE: PrivacyOutcome.CHANNEL_UNAVAILABLE,
        PrivacyReason.NEVER_SEND_DETECTED: PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
        PrivacyReason.AUTHORIZATION_EXPIRED: PrivacyOutcome.APPROVAL_EXPIRED,
        PrivacyReason.AUTHORIZATION_STALE: PrivacyOutcome.APPROVAL_EXPIRED,
        PrivacyReason.AUTHORIZATION_REUSED: PrivacyOutcome.APPROVAL_EXPIRED,
        PrivacyReason.DEADLINE_EXPIRED: PrivacyOutcome.TIMEOUT,
        PrivacyReason.PROVIDER_UNAVAILABLE: PrivacyOutcome.TRANSPORT_FAILED,
        PrivacyReason.AUDIT_FAILED: PrivacyOutcome.AUDIT_FAILED,
        PrivacyReason.POLICY_DENIED: PrivacyOutcome.BLOCKED_BY_POLICY,
    }
)


class ExternalProviderFactory(Protocol):
    """Credential-free, per-binding external provider factory installed by daemon composition.

    Only ``PolicyEnforcingOutboundGateway`` may hold or invoke one. Construction of the factory
    itself must never require a credential or perform network I/O; only :meth:`build_evaluator`
    receives a freshly minted, dispatch-bound credential handle.
    """

    def render(self, case: ApprovedOutboundCase) -> bytes:
        """Deterministically render the exact final application request body; no I/O."""
        ...

    def build_evaluator(
        self,
        binding: ProviderAttemptAuthBinding,
        credential: ProviderCredentialHandle | ExternalRuntimeAuthority,
        request_commitment: RequestCommitment,
    ) -> SemanticEvaluatorPort:
        """Build a one-attempt evaluator bound to this exact credential handle and commitment."""
        ...


class ProviderCredentialMinter(Protocol):
    """The narrow service-vault boundary that mints one exact dispatch-bound credential."""

    async def mint(self, binding: ProviderAttemptAuthBinding) -> ProviderCredentialHandle: ...


type RepositoryAuthorityValidator = Callable[[AuthorizationScope, str], Awaitable[bool]]


@dataclass(frozen=True, slots=True)
class ProviderRegistry:
    """One immutable, generation-fenced snapshot of currently permitted provider adapters.

    Only :meth:`PolicyEnforcingOutboundGateway.reconcile_policy` constructs and swaps this snapshot.
    It has no default adapter, wildcard provider, generic URL, redirect, or fallback: every entry is
    keyed by the exact :class:`ProviderBinding` the durable policy currently permits.
    """

    policy_id: str
    policy_version: int
    policy_generation: int
    policy_digest: str
    repository_privacy_commitment: str | None
    authority_digest: str
    service_generation: int
    vault_generation: int
    human_authority_digest: str
    external: Mapping[ProviderBinding, ExternalProviderFactory]
    local_model: tuple[ProviderBinding, SemanticEvaluatorPort] | None
    require_current_provider_data_use_evidence: bool = False
    # The outside-workspace roots the same policy admits (#1118 unit 1): a case whose inputs were
    # read beneath a root not listed here is refused at consume.
    admitted_input_roots: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.admitted_input_roots) is not tuple:
            raise TypeError("provider_registry_input_roots_invalid")
        if self.repository_privacy_commitment is not None:
            validate_commitment(self.repository_privacy_commitment)
        validate_sha256_digest(self.authority_digest)
        if type(self.external) is not MappingProxyType:
            raise TypeError("provider_registry_external_not_immutable")
        if self.local_model is not None and type(self.local_model) is not tuple:
            raise TypeError("provider_registry_local_model_invalid")
        if type(self.require_current_provider_data_use_evidence) is not bool:
            raise TypeError("provider_registry_data_use_guard_invalid")

    def resolve_external(self, binding: ProviderBinding) -> ExternalProviderFactory | None:
        return self.external.get(binding)

    def resolve_local(self, binding: ProviderBinding) -> SemanticEvaluatorPort | None:
        if self.local_model is not None and self.local_model[0] == binding:
            return self.local_model[1]
        return None

    def data_use_profile(self, binding: ProviderBinding) -> ProviderDataUseProfile | None:
        factory = self.resolve_external(binding)
        if factory is None:
            return None
        profile = getattr(factory, "profile", None)
        data_use = getattr(profile, "data_use_profile", None)
        return data_use if type(data_use) is ProviderDataUseProfile else None


def _llm_bindings(policy: PrivacyPolicy) -> tuple[ProviderBinding, ...]:
    """Every external destination the policy authorizes, primary first (at most two)."""

    llm = next(
        item for item in policy.channel_policies if item.channel is EgressChannel.LLM_INFERENCE
    )
    if not policy.network_egress_permitted or not llm.enabled:
        return ()
    return llm.authorized_provider_bindings


def _local_binding(policy: PrivacyPolicy) -> ProviderBinding | None:
    return policy.local_model_binding if policy.local_model_enabled else None


async def _best_effort_close(target: object) -> None:
    closer = getattr(target, "close", None) or getattr(target, "aclose", None)
    if closer is None:
        return
    try:
        result = closer()
        if asyncio.iscoroutine(result):
            await result
    except Exception:  # noqa: BLE001 - closure of a foreign adapter must never raise
        return


class PolicyEnforcingOutboundGateway(OutboundGatewayPort):
    """The sole gateway allowed to own AI-powered review provider transports.

    Construction receives only verified credential-free factory builders, the privacy audit
    authority needed for atomic consumption, the exact same :class:`PrivacyClassifierPort` instance
    used by the application coordinator, one opaque ``MacKeyHandle(purpose=privacy_audit)``, and a
    narrow service-vault credential minter. It never reads environment/config secrets and never
    discovers endpoints on its own.
    """

    __slots__ = (
        "_audit",
        "_audit_mac",
        "_authority_epoch",
        "_classifier",
        "_clock",
        "_close_task",
        "_closed",
        "_credential_minter",
        "_external_factory_builders",
        "_ids",
        "_lock",
        "_local_model_registry",
        "_local_model_resolver",
        "_registry",
        "_receipt_writes",
        "_repository_authority_validator",
    )

    def __init__(
        self,
        *,
        external_factory_builders: Mapping[ProviderBinding, Callable[[], ExternalProviderFactory]],
        local_model_registry: InstalledLocalModelProfileRegistry,
        local_model_resolver: LocalModelSocketResolverPort | None,
        credential_minter: ProviderCredentialMinter,
        audit: PrivacyAuditPort,
        classifier: PrivacyClassifierPort,
        audit_mac: MacKeyHandle,
        clock: ClockPort,
        ids: IdPort,
        repository_authority_validator: RepositoryAuthorityValidator | None = None,
    ) -> None:
        if type(local_model_registry) is not InstalledLocalModelProfileRegistry:
            raise TypeError("privacy_gateway_local_model_registry_invalid")
        self._external_factory_builders = dict(external_factory_builders)
        self._local_model_registry = local_model_registry
        self._local_model_resolver = local_model_resolver
        self._credential_minter = credential_minter
        self._audit = audit
        self._classifier = classifier
        self._audit_mac = audit_mac
        self._clock = clock
        self._ids = ids
        self._repository_authority_validator = repository_authority_validator
        self._lock = asyncio.Lock()
        self._authority_epoch = 0
        self._registry: ProviderRegistry | None = None
        self._closed = False
        self._close_task: asyncio.Task[None] | None = None
        self._receipt_writes: set[asyncio.Task[None]] = set()

    def _current_registry(self) -> ProviderRegistry | None:
        """Read the live snapshot through a call boundary so static narrowing never assumes away
        a concurrent :meth:`close`/:meth:`close_revoked`/:meth:`reconcile_policy` mutation that can
        happen during an ``await`` elsewhere in this coroutine."""

        return self._registry

    def configured_provider_ids(self) -> tuple[str, ...]:
        """Return bounded structural provider IDs with verified factory builders."""

        return tuple(
            sorted(
                {binding.provider_id for binding in self._external_factory_builders},
                key=str.encode,
            )
        )

    def connected_provider_ids(self) -> tuple[str, ...]:
        """Return provider IDs present in the current generation-fenced registry."""

        registry = self._current_registry()
        if registry is None:
            return ()
        connected = {binding.provider_id for binding in registry.external}
        if registry.local_model is not None:
            connected.add(registry.local_model[0].provider_id)
        return tuple(sorted(connected, key=str.encode))

    def bound_data_use_profile(self, binding: ProviderBinding) -> ProviderDataUseProfile | None:
        """Return the nonsecret data-use profile of the live factory for this exact binding.

        ``None`` means no live factory, so admission fails closed rather than treating an absent
        registry as satisfied evidence.
        """

        if type(binding) is not ProviderBinding:
            raise TypeError("privacy_gateway_provider_binding_invalid")
        registry = self._current_registry()
        if registry is None:
            return None
        return registry.data_use_profile(binding)

    def has_connected_provider_binding(self, binding: ProviderBinding) -> bool:
        """Return whether the exact configured binding is live in the current registry."""

        if type(binding) is not ProviderBinding:
            raise TypeError("privacy_gateway_provider_binding_invalid")
        registry = self._current_registry()
        if registry is None:
            return False
        return (
            registry.resolve_external(binding) is not None
            or registry.resolve_local(binding) is not None
        )

    # -- reconciliation -----------------------------------------------------------------------

    async def reconcile_policy(
        self, policy: EffectivePrivacyPolicy, human_authority: HumanAuthorityCapability
    ) -> ProviderReconciliation:
        """Reconcile a policy without inventing repository authority.

        A machine policy may still reconcile local-only capability, but it cannot construct an
        external provider factory. Repository-aware callers use
        :meth:`reconcile_repository_policy` with the exact authority digest returned by the
        policy store.
        """

        return await self._reconcile_policy(
            policy,
            human_authority,
            repository_privacy_commitment=None,
            authority_digest=policy.effective_digest,
        )

    async def reconcile_repository_policy(
        self,
        policy: EffectivePrivacyPolicy,
        human_authority: HumanAuthorityCapability,
        *,
        repository_privacy_commitment: str,
        authority_digest: str,
    ) -> ProviderReconciliation:
        if policy.policy.effective_scope.workspace_ref_commitment != repository_privacy_commitment:
            raise ValueError("privacy_gateway_repository_scope_mismatch")
        authority_epoch = await self._validated_repository_authority_epoch(
            policy.policy.effective_scope, authority_digest
        )
        if authority_epoch is None:
            return await self._reconcile_policy(
                policy,
                human_authority,
                repository_privacy_commitment=None,
                authority_digest=authority_digest,
            )
        return await self._reconcile_policy(
            policy,
            human_authority,
            repository_privacy_commitment=repository_privacy_commitment,
            authority_digest=authority_digest,
            authority_scope=policy.policy.effective_scope,
            authority_epoch=authority_epoch,
        )

    async def _reconcile_policy(
        self,
        policy: EffectivePrivacyPolicy,
        human_authority: HumanAuthorityCapability,
        *,
        repository_privacy_commitment: str | None,
        authority_digest: str,
        authority_scope: AuthorizationScope | None = None,
        authority_epoch: int | None = None,
    ) -> ProviderReconciliation:
        if type(policy) is not EffectivePrivacyPolicy:
            raise TypeError("privacy_gateway_effective_policy_invalid")
        if type(human_authority) is not HumanAuthorityCapability:
            raise TypeError("privacy_gateway_human_authority_invalid")

        async with self._lock:
            if self._closed:
                return ProviderReconciliation(policy.generation, 0, 0, ())
            if repository_privacy_commitment is not None and (
                authority_scope is None or authority_epoch != self._authority_epoch
            ):
                return ProviderReconciliation(policy.generation, 0, 0, ())
            previous = self._registry
            allowed_external = (
                _llm_bindings(policy.policy) if repository_privacy_commitment is not None else ()
            )
            allowed_local = _local_binding(policy.policy)
            # Phase 1: install an immediate deny fence for anything the new policy no longer
            # permits, before any (possibly slow) candidate construction happens outside the lock.
            fenced_external: dict[ProviderBinding, ExternalProviderFactory] = {}
            fenced_local: tuple[ProviderBinding, SemanticEvaluatorPort] | None = None
            stale_external: dict[ProviderBinding, ExternalProviderFactory] = {}
            stale_local: tuple[ProviderBinding, SemanticEvaluatorPort] | None = None
            if previous is not None:
                for binding, factory in previous.external.items():
                    if binding in allowed_external:
                        fenced_external[binding] = factory
                    else:
                        stale_external[binding] = factory
                if previous.local_model is not None:
                    if previous.local_model[0] == allowed_local:
                        fenced_local = previous.local_model
                    else:
                        stale_local = previous.local_model
            phase_registry = ProviderRegistry(
                policy.policy.policy_id,
                policy.policy.version,
                policy.generation,
                policy.effective_digest,
                repository_privacy_commitment,
                authority_digest,
                human_authority.service_generation,
                human_authority.vault_generation,
                human_authority.capability_digest,
                MappingProxyType(fenced_external),
                fenced_local,
                policy.policy.require_current_provider_data_use_evidence,
                policy.policy.admitted_input_roots,
            )
            self._registry = phase_registry

        for factory in stale_external.values():
            await _best_effort_close(factory)
        if stale_local is not None:
            await _best_effort_close(stale_local[1])

        # Phase 2: outside the lock, build newly allowed candidates. No inference/capability
        # request occurs here and no credential handle is minted.
        new_external: dict[ProviderBinding, ExternalProviderFactory] = dict(fenced_external)
        unavailable: list[tuple[str, str]] = []
        # Each authorized destination is admitted on its own: a fallback whose factory is absent
        # or fails to build is reported as unavailable without fencing the primary, and the
        # reverse holds too. Bounded at two bindings by the policy row.
        for candidate_binding in allowed_external:
            if (
                candidate_binding in new_external
                or human_authority.source == "unavailable"
                or not human_authority.external_activation_allowed
            ):
                continue
            builder = self._external_factory_builders.get(candidate_binding)
            if builder is None:
                unavailable.append((_binding_digest(candidate_binding), "factory_unavailable"))
                continue
            assert authority_scope is not None
            build_epoch = await self._validated_repository_authority_epoch(
                authority_scope, authority_digest
            )
            if build_epoch is None:
                continue
            async with self._lock:
                if (
                    not self._closed
                    and self._current_registry() is phase_registry
                    and build_epoch == self._authority_epoch
                ):
                    try:
                        # Construction is the capability-admission boundary. Holding the same
                        # lock as close_revoked makes either revocation or this exact
                        # construction win, never both in an ambiguous order.
                        new_external[candidate_binding] = builder()
                    except Exception:  # noqa: BLE001 - bounded foreign failure
                        unavailable.append(
                            (_binding_digest(candidate_binding), "factory_construction_failed")
                        )

        new_local = fenced_local
        if (
            allowed_local is not None
            and new_local is None
            and self._local_model_resolver is not None
        ):
            # `InstalledLocalModelProfileRegistry.resolve` is keyed by the release-artifact's own
            # `(profile_id, profile_version)`, which the privacy policy's `ProviderBinding` does not
            # carry; the only correlation available here is the endpoint profile identity, so the
            # exact installed entry is found by matching that instead.
            profile = next(
                (
                    entry
                    for entry in self._local_model_registry.entries
                    if entry.endpoint_profile_id == allowed_local.endpoint_profile_id
                    and entry.endpoint_profile_version == allowed_local.endpoint_profile_version
                ),
                None,
            )
            if profile is None:
                unavailable.append(
                    (_binding_digest(allowed_local), "local_model_profile_unavailable")
                )
            else:
                try:
                    handle = self._local_model_resolver.resolve(profile)
                    if (
                        handle.service_generation == human_authority.service_generation
                        and handle.profile_digest == profile.capability_evidence_digest
                    ):
                        new_local = (
                            allowed_local,
                            LocalModelEvaluator(
                                profile, handle, self._clock, reply_schemas=REVIEWER_REPLY_SCHEMAS
                            ),
                        )
                    else:
                        unavailable.append(
                            (_binding_digest(allowed_local), "local_model_generation_mismatch")
                        )
                except Exception:  # noqa: BLE001 - a foreign resolver failure is bounded here
                    unavailable.append(
                        (_binding_digest(allowed_local), "local_model_resolve_failed")
                    )

        # Phase 3: re-take the lock, recheck currency, and atomically publish only matching
        # candidates. Stale candidates built against an outdated snapshot are closed, not adopted.
        async with self._lock:
            current = self._current_registry()
            if (
                self._closed
                or current is None
                or current is not phase_registry
                or (
                    repository_privacy_commitment is not None
                    and authority_epoch != self._authority_epoch
                )
            ):
                for binding, factory in new_external.items():
                    if binding not in fenced_external:
                        await _best_effort_close(factory)
                if new_local is not None and new_local is not fenced_local:
                    await _best_effort_close(new_local[1])
                return ProviderReconciliation(policy.generation, 0, 0, tuple(sorted(unavailable)))
            activated = (
                len(new_external)
                - len(fenced_external)
                + (1 if new_local is not None and new_local is not fenced_local else 0)
            )
            deactivated = len(stale_external) + (1 if stale_local is not None else 0)
            self._registry = ProviderRegistry(
                policy.policy.policy_id,
                policy.policy.version,
                policy.generation,
                policy.effective_digest,
                repository_privacy_commitment,
                authority_digest,
                human_authority.service_generation,
                human_authority.vault_generation,
                human_authority.capability_digest,
                MappingProxyType(new_external),
                new_local,
                policy.policy.require_current_provider_data_use_evidence,
                policy.policy.admitted_input_roots,
            )
        return ProviderReconciliation(
            policy.generation, activated, deactivated, tuple(sorted(unavailable))
        )

    # -- external dispatch ---------------------------------------------------------------------

    async def dispatch_external_semantic(
        self,
        case: ApprovedOutboundCase,
        authorization: EgressAuthorization,
        deadline: Deadline,
    ) -> SemanticResult:
        if type(case) is not ApprovedOutboundCase:
            raise TypeError("privacy_gateway_case_invalid")
        if type(authorization) is not EgressAuthorization:
            raise TypeError("privacy_gateway_authorization_invalid")
        if type(deadline) is not Deadline:
            raise TypeError("privacy_gateway_deadline_invalid")

        registry = self._registry
        now_monotonic = self._clock.monotonic_seconds()
        now_utc = self._clock.now_utc()

        if not await self._repository_authority_is_current(authorization.scope, registry):
            return await self._preconsume_failure(
                case, authorization, PrivacyReason.AUTHORIZATION_STALE
            )

        reason = self._predispatch_reason(
            case, authorization, registry, deadline, now_monotonic, now_utc
        )
        if reason is not None:
            return await self._preconsume_failure(case, authorization, reason)
        assert registry is not None

        factory = registry.resolve_external(case.provider_binding)
        if factory is None:
            return await self._preconsume_failure(
                case, authorization, PrivacyReason.CHANNEL_UNAVAILABLE
            )

        dispatch_id = self._ids.new(IdKind.EGRESS_DISPATCH)

        try:
            body = factory.render(case)
        except Exception:  # noqa: BLE001 - a foreign factory failure is bounded here
            return await self._preconsume_failure(
                case, authorization, PrivacyReason.PROVIDER_UNAVAILABLE
            )
        if type(body) is not bytes or not body or case.payload not in body:
            return await self._preconsume_failure(
                case, authorization, PrivacyReason.PROVIDER_UNAVAILABLE
            )

        final_findings = _final_scan(self._classifier, body, case.credential_heuristic)
        if final_findings:
            return await self._preconsume_failure(
                case,
                authorization,
                PrivacyReason.NEVER_SEND_DETECTED,
                scan_stage=ReceiptSecretScanStage.RENDERED_BODY,
                scan_match_count=len(final_findings),
            )

        body_digest = "sha256:" + hashlib.sha256(body).hexdigest()
        commitment = privacy_request_commitment(body, self._audit_mac)

        # Recheck after deterministic rendering and immediately before a credential handle can
        # exist. Repository revocation is allowed to race with rendering, but never with minting.
        if not await self._repository_authority_is_current(authorization.scope, registry):
            return await self._preconsume_failure(
                case, authorization, PrivacyReason.AUTHORIZATION_STALE
            )

        binding = ProviderAttemptAuthBinding(
            provider_id=case.provider_binding.provider_id,
            model_id=case.provider_binding.model_id,
            endpoint_profile_id=case.provider_binding.endpoint_profile_id,
            endpoint_profile_version=case.provider_binding.endpoint_profile_version,
            purpose=case.purpose,
            authorization_scope_digest=_scope_digest(authorization.scope),
            purpose_digest=canonical_digest({"purpose": case.purpose}),
            dispatch_id=dispatch_id,
            request_body_digest=body_digest,
            service_generation=registry.service_generation,
            monotonic_deadline=deadline.monotonic_deadline,
        )

        credential_authority = getattr(
            factory, "credential_authority", "finishup_vault_api_credential"
        )
        if credential_authority == "external_runtime_oauth":
            credential: ProviderCredentialHandle | ExternalRuntimeAuthority = (
                ExternalRuntimeAuthority(
                    dispatch_id=dispatch_id,
                    request_body_digest=body_digest,
                    request_commitment=commitment,
                    service_generation=registry.service_generation,
                    monotonic_deadline=deadline.monotonic_deadline,
                )
            )
        elif credential_authority == "finishup_vault_api_credential":
            try:
                credential = await self._credential_minter.mint(binding)
            except Exception:  # noqa: BLE001 - a foreign vault failure is bounded here
                return await self._preconsume_failure(
                    case, authorization, PrivacyReason.PROVIDER_UNAVAILABLE
                )
        else:
            return await self._preconsume_failure(
                case, authorization, PrivacyReason.PROVIDER_UNAVAILABLE
            )

        if self._closed or self._current_registry() is not registry:
            return await self._preconsume_failure(
                case, authorization, PrivacyReason.AUTHORIZATION_STALE
            )

        try:
            evaluator = factory.build_evaluator(
                binding,
                credential,
                RequestCommitment(PRIVACY_REQUEST_COMMITMENT_ALGORITHM, commitment),
            )
        except Exception:  # noqa: BLE001 - a foreign factory failure is bounded here
            return await self._preconsume_failure(
                case, authorization, PrivacyReason.PROVIDER_UNAVAILABLE
            )

        # Validate without the gateway lock so a validator is free to trigger close_revoked. The
        # captured epoch is then consumed under that same lock with the audit CAS: revocation that
        # wins first makes this attempt stale, while revocation after the CAS is ordered after an
        # admitted physical attempt.
        final_authority_epoch = await self._validated_repository_authority_epoch(
            authorization.scope, registry.authority_digest
        )
        # This gateway is the only holder of the exact final request body, its keyed commitment,
        # and the authorization/registry binding a dispatch receipt must carry, and the audit
        # deliberately retains no plaintext. Build the receipt this attempt owes on an unknown
        # outcome before consume; the audit parks it in the consume transaction itself (#1118
        # unit 1), so no crash leaves a consumed authorization without its owed receipt.
        dispatch_started_at = self._clock.now_utc()
        unknown_receipt = self._attempt_receipt(
            case,
            authorization,
            registry,
            dispatch_id,
            dispatch_started_at,
            commitment,
            body,
            _unknown_outcome_result(case, binding),
            PrivacyOutcome.TRANSPORT_FAILED,
            PrivacyReason.OUTCOME_UNKNOWN,
        )
        admission_failure: PrivacyReason | None = None
        async with self._lock:
            if (
                final_authority_epoch is None
                or self._closed
                or self._current_registry() is not registry
                or final_authority_epoch != self._authority_epoch
                or not _roots_admitted(case.input_roots, registry)
            ):
                admission_failure = PrivacyReason.AUTHORIZATION_STALE
            else:
                try:
                    await self._audit.consume(
                        authorization.authorization_id,
                        dispatch_id,
                        now_utc,
                        owed_receipt=unknown_receipt,
                    )
                except Exception:  # noqa: BLE001 - a lost consume race is bounded here
                    admission_failure = PrivacyReason.AUTHORIZATION_REUSED
        if admission_failure is not None:
            return await self._preconsume_failure(case, authorization, admission_failure)

        # From here on the physical attempt is admitted: no failure below can restore authority,
        # only its actual terminal or `outcome_unknown` receipt is produced.
        receipt: EgressReceipt | None = None
        try:
            # Structural progress only (issue #571 A2). A runtime-backed evaluator reports its own
            # launch, validation, and sampling phases; a direct request samples immediately.
            await report_semantic_progress(SemanticProgressPhase.CASE_ADMITTED)
            if credential_authority != "external_runtime_oauth":
                await report_semantic_progress(SemanticProgressPhase.PROVIDER_SAMPLING)
            try:
                result = await evaluator.evaluate(case, deadline)
                result = _with_policy_digest(result, case)
                result = _with_request_commitment(result, commitment)
                outcome, receipt_reason = _result_outcome(result)
            except Exception:  # noqa: BLE001 - ambiguous transport never leaks native text
                result = _unknown_outcome_result(case, binding)
                outcome = PrivacyOutcome.TRANSPORT_FAILED
                receipt_reason = PrivacyReason.OUTCOME_UNKNOWN
            receipt = self._attempt_receipt(
                case,
                authorization,
                registry,
                dispatch_id,
                dispatch_started_at,
                commitment,
                body,
                result,
                outcome,
                receipt_reason,
            )
            try:
                await self._audit.complete_egress(dispatch_id, receipt)
            except Exception:  # noqa: BLE001 - best-effort: caller retains the real result
                pass
            return result
        except BaseException:
            # Cover every suspension after consume: parking, provider I/O, and the final write.
            # Preserve a real result already obtained; otherwise adjudicate unknown now, not at
            # the earlier parking time. Cleanup never dispatches or restores authority.
            cancelled_receipt = receipt or replace(
                unknown_receipt, finished_at=max(self._clock.now_utc(), unknown_receipt.finished_at)
            )
            await self._shielded_receipt(dispatch_id, cancelled_receipt)
            raise

    def _predispatch_reason(
        self,
        case: ApprovedOutboundCase,
        authorization: EgressAuthorization,
        registry: ProviderRegistry | None,
        deadline: Deadline,
        now_monotonic: float,
        now_utc: datetime,
    ) -> PrivacyReason | None:
        if self._closed or registry is None:
            return PrivacyReason.CHANNEL_UNAVAILABLE
        if (
            case.authorization_id != authorization.authorization_id
            or case.case_digest != authorization.case_digest
            or case.provider_binding != authorization.provider_binding
            or case.purpose != authorization.purpose
        ):
            return PrivacyReason.AUTHORIZATION_REUSED
        if (
            case.policy_digest != authorization.policy_digest
            or registry.policy_digest != authorization.policy_digest
            or registry.service_generation != authorization.service_generation
        ):
            return PrivacyReason.AUTHORIZATION_STALE
        if authorization.scope.workspace_ref_commitment != registry.repository_privacy_commitment:
            return PrivacyReason.AUTHORIZATION_STALE
        if deadline.expired(now_monotonic):
            return PrivacyReason.DEADLINE_EXPIRED
        if now_utc >= authorization.expires_at:
            return PrivacyReason.AUTHORIZATION_EXPIRED
        if registry.require_current_provider_data_use_evidence:
            data_use = registry.data_use_profile(case.provider_binding)
            if data_use is None or not data_use.recommendation_eligible(now_utc):
                return PrivacyReason.POLICY_DENIED
        return None

    async def _repository_authority_is_current(
        self, scope: AuthorizationScope, registry: ProviderRegistry | None
    ) -> bool:
        if (
            registry is None
            or registry.repository_privacy_commitment is None
            or scope.workspace_ref_commitment != registry.repository_privacy_commitment
        ):
            return False
        validator = self._repository_authority_validator
        if validator is None:
            return False
        try:
            return await validator(scope, registry.authority_digest) is True
        except Exception:
            return False

    async def _validated_repository_authority_epoch(
        self, scope: AuthorizationScope, authority_digest: str
    ) -> int | None:
        """Return an optimistic epoch only for one exact live repository snapshot.

        Callers must compare the returned value again while holding ``_lock`` at the capability
        boundary. A validator may itself close the registry; capturing the epoch before invoking
        it makes that closure observable without ever invoking foreign code under the lock.
        """

        validator = self._repository_authority_validator
        if validator is None:
            return None
        async with self._lock:
            if self._closed:
                return None
            authority_epoch = self._authority_epoch
        try:
            current = await validator(scope, authority_digest)
        except Exception:
            return None
        return authority_epoch if current is True else None

    async def _preconsume_failure(
        self,
        case: ApprovedOutboundCase,
        authorization: EgressAuthorization,
        reason: PrivacyReason,
        *,
        scan_stage: ReceiptSecretScanStage = ReceiptSecretScanStage.NOT_RUN,
        scan_match_count: int = 0,
    ) -> SemanticResult:
        outcome = _PRECONSUME_OUTCOME[reason]
        now = self._clock.now_utc()
        authorization_id = (
            None if outcome in _NO_AUTHORIZATION_ID_OUTCOMES else authorization.authorization_id
        )
        receipt = EgressReceipt(
            "1.1.0",
            self._ids.new(IdKind.EGRESS_RECEIPT),
            case.request_id,
            authorization.privacy_proposal_id,
            EgressChannel.LLM_INFERENCE,
            outcome,
            now,
            authorization.scope,
            case.purpose,
            case.provider_binding,
            _bounded_policy_binding(authorization),
            ConsentSource.NONE,
            (),
            case.blocked_categories,
            ReceiptCounts(
                len(case.included_item_ids),
                0,
                len(case.included_item_ids),
                0,
                len(case.included_item_ids),
                case.byte_count,
                0,
                None,
                None,
            ),
            ReceiptTransformations(
                0,
                case.redacted_span_count,
                len(case.included_item_ids),
            ),
            ReceiptSecretScan(
                _SCAN.version,
                _SCAN.profile_digest,
                scan_match_count,
                scan_stage is not ReceiptSecretScanStage.NOT_RUN and scan_match_count == 0,
                scan_stage,
                reason if scan_stage is ReceiptSecretScanStage.NOT_RUN else None,
                case.credential_heuristic,
            ),
            reason,
            1,
            authorization_id=authorization_id,
            withheld_item_ids=case.withheld_item_ids,
            origin_operation=egress_origin_operation(case.purpose, case.included_item_ids),
        )
        # Every pre-dispatch refusal returns the same public shape (`unavailable`, no receipt id,
        # so the composition reports `receipt_persistence_unknown`). The exact closed reason is
        # owner-only material; record it under the case's request id so `finishup service
        # diagnostics --request-id` can name why nothing was sent.
        record_bounded_event_without_raising(
            component="privacy_gateway",
            operation="egress_preconsume",
            reason=reason.value,
            request_id=case.request_id,
        )
        try:
            await self._audit.complete_decision(authorization.privacy_proposal_id, receipt)
        except Exception as exc:  # noqa: BLE001 - best-effort: the bounded result still returns
            record_classified_exception_without_raising(
                exc,
                component="privacy_gateway",
                operation="egress_preconsume_receipt",
                request_id=case.request_id,
            )
        return _preconsume_result(case, reason)

    async def _shielded_receipt(self, dispatch_id: str, receipt: EgressReceipt) -> None:
        """Keep ownership of the local receipt write through repeated cancellation."""

        pending = asyncio.create_task(self._audit.complete_egress(dispatch_id, receipt))
        self._receipt_writes.add(pending)

        def finished(task: asyncio.Task[None]) -> None:
            self._receipt_writes.discard(task)
            if not task.cancelled():
                task.exception()  # Observe a failed best-effort write; never redispatch.

        pending.add_done_callback(finished)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 2.0
        while not pending.done():
            remaining = deadline - loop.time()
            if remaining <= 0:
                return  # Owned write continues; parked receipt remains restart recovery material.
            try:
                await asyncio.wait_for(asyncio.shield(pending), remaining)
            except asyncio.CancelledError:
                continue
            except TimeoutError:
                return
            except Exception:  # noqa: BLE001 - a failed audit write grants no retry
                return

    def _attempt_receipt(
        self,
        case: ApprovedOutboundCase,
        authorization: EgressAuthorization,
        registry: ProviderRegistry,
        dispatch_id: str,
        dispatch_started_at: datetime,
        commitment: str,
        body: bytes,
        result: SemanticResult,
        outcome: PrivacyOutcome,
        reason: PrivacyReason | None,
    ) -> EgressReceipt:
        runtime_evidence = result.provenance.runtime_evidence
        disclosed = runtime_evidence is None or runtime_evidence.case_disclosed
        included_items = len(case.included_item_ids) if disclosed else 0
        final_bytes = case.byte_count if disclosed else 0
        return EgressReceipt(
            "1.1.0",
            self._ids.new(IdKind.EGRESS_RECEIPT),
            case.request_id,
            authorization.privacy_proposal_id,
            EgressChannel.LLM_INFERENCE,
            outcome,
            self._clock.now_utc(),
            authorization.scope,
            case.purpose,
            case.provider_binding,
            ReceiptPolicyBinding(
                registry.policy_id,
                registry.policy_version,
                registry.policy_digest,
                _scope_digest(authorization.scope),
            ),
            authorization.consent_source,
            case.approved_categories,
            case.blocked_categories,
            ReceiptCounts(
                len(case.included_item_ids),
                included_items,
                len(case.included_item_ids) - included_items,
                included_items,
                len(case.included_item_ids) - included_items,
                case.byte_count,
                final_bytes,
                case.token_count,
                len(body) if disclosed else 0,
            ),
            ReceiptTransformations(
                0,
                case.redacted_span_count,
                len(case.included_item_ids) - included_items,
            ),
            ReceiptSecretScan(
                _SCAN.version,
                _SCAN.profile_digest,
                0,
                True,
                ReceiptSecretScanStage.RENDERED_BODY,
                credential_heuristic=case.credential_heuristic,
            ),
            reason,
            1,
            authorization_id=authorization.authorization_id,
            dispatch_id=dispatch_id,
            dispatch_started_at=dispatch_started_at,
            request_commitment=RequestCommitment(PRIVACY_REQUEST_COMMITMENT_ALGORITHM, commitment),
            withheld_item_ids=case.withheld_item_ids,
            origin_operation=egress_origin_operation(case.purpose, case.included_item_ids),
        )

    # -- local dispatch -------------------------------------------------------------------------

    async def dispatch_local_semantic(
        self, case: ApprovedLocalDisclosureCase, deadline: Deadline
    ) -> SemanticResult:
        if (
            type(case) is not ApprovedLocalDisclosureCase
            or case.sink is not LocalDisclosureSink.LOCAL_MODEL
        ):
            raise TypeError("privacy_gateway_local_case_invalid")
        if type(deadline) is not Deadline:
            raise TypeError("privacy_gateway_deadline_invalid")

        registry = self._current_registry()
        if self._closed or registry is None or registry.local_model is None or case.binding is None:
            return _local_unavailable_result(case)
        binding, evaluator = registry.local_model
        if case.binding != binding or case.policy_digest != registry.policy_digest:
            return _local_unavailable_result(case)
        if _final_scan(self._classifier, case.payload, case.credential_heuristic):
            return _local_unavailable_result(
                case, failure_class=SemanticFailureClass.RESPONSE_CONTENT
            )

        now = self._clock.now_utc()
        # Consume under the same lock policy mutation holds (#1118 unit 1, E2E-2): a root removal
        # or tightening that commits first clears this registry, so the consume sees it.
        async with self._lock:
            if (
                self._closed
                or self._current_registry() is not registry
                or not _roots_admitted(case.input_roots, registry)
            ):
                return _local_unavailable_result(case)
            try:
                await self._audit.consume_local(case.privacy_proposal_id, case.case_digest, now)
            except Exception:  # noqa: BLE001 - a lost consume race is bounded here
                return _local_unavailable_result(case)

        await report_semantic_progress(SemanticProgressPhase.CASE_ADMITTED)
        await report_semantic_progress(SemanticProgressPhase.PROVIDER_SAMPLING)
        result = await evaluator.evaluate(case, deadline)
        # Only the rebind is fenced here: an evaluator failure keeps propagating exactly as before.
        try:
            return _with_policy_digest(result, case)
        except ValueError:
            return _local_unavailable_result(case)

    # -- lifecycle ------------------------------------------------------------------------------

    async def close_revoked(self, policy_generation: int) -> None:
        if type(policy_generation) is not int or policy_generation < 1:
            raise TypeError("privacy_gateway_generation_invalid")
        async with self.authority_mutation_fence():
            pass

    @asynccontextmanager
    async def authority_mutation_fence(self) -> AsyncGenerator[None]:
        """Linearize durable authority mutation with reconcile and dispatch admission.

        The lock remains held while the caller mutates the policy store. Reconciliation and final
        authorization consume therefore observe either the complete old authority or the complete
        new authority, never the released pre-commit gap. Cleanup is intentionally deferred until
        after release because closing adapters may run foreign async code.
        """

        registry: ProviderRegistry | None = None
        await self._lock.acquire()
        try:
            registry = self._registry
            self._authority_epoch += 1
            self._registry = None
            yield
        finally:
            self._lock.release()
            await _close_registry(registry)

    async def close(self) -> None:
        async with self._lock:
            if self._close_task is None:
                self._closed = True
                self._authority_epoch += 1
                registry = self._registry
                self._registry = None
                self._close_task = asyncio.create_task(_close_registry(registry))
            task = self._close_task
        await task


def _roots_admitted(roots: tuple[str, ...], registry: ProviderRegistry) -> bool:
    """Whether every outside root a case's inputs were read beneath is still admitted (E2E-2)."""

    return set(roots) <= set(registry.admitted_input_roots)


def _binding_digest(binding: ProviderBinding) -> str:
    return canonical_digest(
        {
            "endpoint_profile_id": binding.endpoint_profile_id,
            "endpoint_profile_version": binding.endpoint_profile_version,
            "model_id": binding.model_id,
            "provider_id": binding.provider_id,
            "transport": binding.transport,
        }
    )


def _bounded_policy_binding(authorization: EgressAuthorization) -> ReceiptPolicyBinding:
    """Use the durably-visible fields on the authorization itself for a preconsume receipt.

    ``EgressAuthorization`` carries ``policy_version``/``policy_digest`` but not a ``policy_id``;
    the exact policy identifier is only reliably known while a matching :class:`ProviderRegistry`
    snapshot is current (see the attempted-receipt path, which uses that snapshot instead). A
    preconsume failure may occur precisely because no such snapshot is current, so this binding
    reuses the authorization's own proposal identifier as a stable, non-widening placeholder policy
    identifier alongside the authorization's real version/digest.
    """

    return ReceiptPolicyBinding(
        authorization.privacy_proposal_id.replace("ppr_", "pvy_", 1),
        authorization.policy_version,
        authorization.policy_digest,
        _scope_digest(authorization.scope),
    )


def _with_request_commitment(result: SemanticResult, commitment: str) -> SemanticResult:
    """Carry the gateway-bound request commitment into the receipt-bound AI-powered review outcome."""

    return replace(result, provenance=replace(result.provenance, request_commitment=commitment))


def _with_policy_digest(result: SemanticResult, case: ApprovedProviderCase) -> SemanticResult:
    """Bind provenance to the policy digest that actually authorized this physical dispatch.

    The gateway, not the provider adapter, is the authority on which policy admitted an attempt: it
    already refuses to dispatch unless ``case.policy_digest`` equals both the authorization's and
    the current registry's policy digest (see :meth:`OutboundPrivacyGateway._predispatch_reason`),
    and it stamps that same value onto :class:`EgressReceipt`. Rebinding here makes provenance and
    the egress receipt agree by construction, and keeps a foreign adapter from ever asserting what
    authorized it.

    A dispatch that reached a provider and succeeded must carry a real digest. An all-zero
    placeholder surviving the rebind means the authorizing policy digest was itself a placeholder,
    so the attempt is refused rather than recorded as if a real policy had authorized it: external
    dispatch degrades to the bounded ``outcome_unknown`` receipt and local dispatch to the bounded
    unavailable result. Genuinely-blocked results that never reached a provider keep their
    :attr:`SemanticStatus.UNAVAILABLE` zeros untouched.
    """

    provenance = replace(
        result.provenance,
        policy_digest=case.policy_digest,
        privacy_policy_digest=case.policy_digest,
    )
    if provenance.status is SemanticStatus.SUCCEEDED and (
        provenance.policy_digest == _ZERO_DIGEST or provenance.privacy_policy_digest == _ZERO_DIGEST
    ):
        raise ValueError("privacy_gateway_provenance_policy_digest_placeholder")
    return replace(result, provenance=provenance)


def _result_outcome(result: SemanticResult) -> tuple[PrivacyOutcome, PrivacyReason | None]:
    if type(result) is SemanticResultSuccess or type(result) is SemanticResultReply:
        return PrivacyOutcome.COMPLETED, None
    if type(result) is SemanticResultRefused:
        return PrivacyOutcome.PROVIDER_REFUSED, PrivacyReason.PROVIDER_REFUSED
    if type(result) is SemanticResultTimeout:
        return PrivacyOutcome.TIMEOUT, PrivacyReason.PROVIDER_TIMEOUT
    if type(result) is SemanticResultInvalid:
        return PrivacyOutcome.INVALID_RESPONSE, PrivacyReason.PROVIDER_INVALID_RESPONSE
    if type(result) is SemanticResultLate:
        return PrivacyOutcome.LATE, PrivacyReason.LATE
    if type(result) is SemanticResultUnavailable:
        runtime = result.provenance.runtime_evidence
        if (
            runtime is not None
            and runtime.turn_acknowledged
            and result.provenance.failure_class is SemanticFailureClass.TRANSPORT
        ):
            return PrivacyOutcome.TRANSPORT_FAILED, PrivacyReason.OUTCOME_UNKNOWN
        return PrivacyOutcome.TRANSPORT_FAILED, PrivacyReason.TRANSPORT_FAILED
    raise TypeError("privacy_gateway_semantic_result_invalid")


def _preconsume_result(case: ApprovedOutboundCase, reason: PrivacyReason) -> SemanticResult:
    if reason is PrivacyReason.DEADLINE_EXPIRED:
        failure_class = SemanticFailureClass.TIMEOUT
    elif reason is PrivacyReason.NEVER_SEND_DETECTED:
        # The rendered-body scan is a privacy refusal, not an endpoint/profile failure. Carry a
        # closed response-content marker so ready composition maps it to BLOCKED_FORBIDDEN_DATA /
        # NEVER_SEND_DETECTED (and therefore semantic_privacy_blocked) instead of transport loss.
        failure_class = SemanticFailureClass.RESPONSE_CONTENT
    else:
        failure_class = SemanticFailureClass.UNSUPPORTED_PROFILE
    return SemanticResultUnavailable(
        ProviderAttemptProvenance(
            provider=case.provider_binding.provider_id,
            endpoint_profile_id=case.provider_binding.endpoint_profile_id,
            endpoint_profile_version=case.provider_binding.endpoint_profile_version,
            model=case.provider_binding.model_id,
            sdk_version="0.0.0",
            prompt_digest=_ZERO_DIGEST,
            schema_digest=_ZERO_DIGEST,
            policy_digest=_ZERO_DIGEST,
            privacy_policy_digest=_ZERO_DIGEST,
            sampling_params=SamplingParams(1),
            latency_ms=0,
            status=SemanticStatus.UNAVAILABLE,
            failure_class=failure_class,
        )
    )


def _unknown_outcome_result(
    case: ApprovedOutboundCase, binding: ProviderAttemptAuthBinding
) -> SemanticResult:
    return SemanticResultUnavailable(
        ProviderAttemptProvenance(
            provider=case.provider_binding.provider_id,
            endpoint_profile_id=case.provider_binding.endpoint_profile_id,
            endpoint_profile_version=case.provider_binding.endpoint_profile_version,
            model=case.provider_binding.model_id,
            sdk_version="0.0.0",
            prompt_digest=binding.request_body_digest,
            schema_digest=binding.request_body_digest,
            policy_digest=_ZERO_DIGEST,
            privacy_policy_digest=_ZERO_DIGEST,
            sampling_params=SamplingParams(1),
            latency_ms=0,
            status=SemanticStatus.UNAVAILABLE,
            failure_class=SemanticFailureClass.TRANSPORT,
        )
    )


def _local_unavailable_result(
    case: ApprovedLocalDisclosureCase,
    *,
    failure_class: SemanticFailureClass = SemanticFailureClass.UNSUPPORTED_PROFILE,
) -> SemanticResult:
    binding = case.binding
    provider = "local-model" if binding is None else binding.provider_id
    endpoint = "unavailable" if binding is None else binding.endpoint_profile_id
    version = "0.0.0" if binding is None else binding.endpoint_profile_version
    model = "unavailable" if binding is None else binding.model_id
    return SemanticResultUnavailable(
        ProviderAttemptProvenance(
            provider=provider,
            endpoint_profile_id=endpoint,
            endpoint_profile_version=version,
            model=model,
            sdk_version="0.0.0",
            prompt_digest=_ZERO_DIGEST,
            schema_digest=_ZERO_DIGEST,
            policy_digest=_ZERO_DIGEST,
            privacy_policy_digest=_ZERO_DIGEST,
            sampling_params=SamplingParams(1),
            latency_ms=0,
            status=SemanticStatus.UNAVAILABLE,
            failure_class=failure_class,
        )
    )


async def _close_registry(registry: ProviderRegistry | None) -> None:
    if registry is None:
        return
    for factory in registry.external.values():
        await _best_effort_close(factory)
    if registry.local_model is not None:
        await _best_effort_close(registry.local_model[1])
