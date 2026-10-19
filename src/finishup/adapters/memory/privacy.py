"""In-memory reference privacy policy and audit adapters."""

from __future__ import annotations

import asyncio
import base64
import hmac
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import cast

from finishup.adapters.privacy.catalog import (
    _json,  # pyright: ignore[reportPrivateUsage]
    _mac,  # pyright: ignore[reportPrivateUsage]
    _policy_for_repository,  # pyright: ignore[reportPrivateUsage]
    _scope_digest,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.privacy import (
    AgentProjectionAuditSubject,
    AuthorizationScope,
    AuthorizationScopeKind,
    DisclosureProposal,
    EgressAuthorization,
    EgressReceipt,
    HumanPrivacyDecision,
    LocalDisclosureReceipt,
    PreDispatchAuditDecision,
    PrivacyAuditSubject,
    PrivacyPolicy,
    ProviderBinding,
    ReceiptSecretScanStage,
)
from finishup.domain.values import validate_sha256_digest
from finishup.ports.clock import ClockPort
from finishup.ports.keys import MacKeyHandle
from finishup.ports.objects import (
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectSource,
    ObjectStorePort,
)
from finishup.ports.privacy import (
    AgentProjectionRequest,
    CompletedAgentProjection,
    ConsumedAuthorization,
    ConsumedLocalDisclosure,
    DisclosureProposalRequest,
    EffectivePrivacyPolicy,
    HumanPolicyDecision,
    LocalDisclosureReceiptView,
    NetworkEgressReceiptView,
    PendingDisclosureEntry,
    PendingDisclosurePage,
    PolicyCommitResult,
    PolicyOverlay,
    PolicyTransitionMember,
    PolicyTransitionProposal,
    PreparedDisclosureReservation,
    PreparedPolicyTransition,
    PrivacyAuditObjectRoots,
    PrivacyAuditReservation,
    PrivacyAuditState,
    PrivacyAuthorityAncestor,
    PrivacyReceiptAudience,
    PrivacyReceiptCursorInvalid,
    PrivacyReceiptPage,
    PrivacyReceiptQuery,
    PrivacyReceiptView,
    RepositoryPrivacyAuthority,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "MemoryPrivacyAudit",
    "MemoryPrivacyCatalogState",
    "MemoryPrivacyPolicyStore",
]

_LOOKUP_DOMAIN = b"yoetz/privacy-audit/lookup/v1\x00"
_PROPOSAL_DOMAIN = b"yoetz/privacy-audit/proposal/v1\x00"
_CONTROL_DOMAIN = b"yoetz/privacy-audit/control-request/v1\x00"
_INTERNAL_RESULT_DOMAIN = b"yoetz/privacy-audit/internal-result/v1\x00"
_PROJECTION_DOMAIN = b"yoetz/privacy-audit/projection/v1\x00"
_APPROVAL_DOMAIN = b"yoetz/privacy-audit/local-approval/v1\x00"
_CURSOR_DOMAIN = b"yoetz/privacy-audit/receipt-cursor/v1\x00"


@dataclass(frozen=True, slots=True)
class _PolicyRow:
    policy: PrivacyPolicy
    generation: int


@dataclass(frozen=True, slots=True)
class _AuditRow:
    reservation: PrivacyAuditReservation
    subject: PrivacyAuditSubject
    status: str
    receipt: LocalDisclosureReceipt | EgressReceipt | None = None
    object_ref: ObjectRef | None = None
    consumed_digest: str | None = None
    authorization_id: str | None = None
    dispatch_id: str | None = None


@dataclass(frozen=True, slots=True)
class _MemoryTransition:
    prepared: PreparedPolicyTransition
    state: str = "pending"
    decision_digest: str | None = None
    result: PolicyCommitResult | None = None
    decided_at: datetime | None = None


@dataclass(slots=True, repr=False)
class MemoryPrivacyCatalogState:
    policies: dict[str, _PolicyRow] = field(default_factory=dict[str, _PolicyRow])
    transitions: dict[str, _MemoryTransition] = field(default_factory=dict[str, _MemoryTransition])
    audit: dict[str, _AuditRow] = field(default_factory=dict[str, _AuditRow])
    routes: dict[str, str] = field(default_factory=dict[str, str])
    root_generation: dict[str, int] = field(default_factory=dict[str, int])
    generation: int = 0
    first_repository_carry_forward_state: str | None = None
    first_repository_carry_forward_commitment: str | None = None
    migration_frontier_policy: PrivacyPolicy | None = None
    legacy_route_entitlements: dict[tuple[str, str], PrivacyPolicy] = field(
        default_factory=dict[tuple[str, str], PrivacyPolicy]
    )
    consumed_legacy_repository_commitments: set[str] = field(default_factory=set[str])

    def __repr__(self) -> str:
        return "MemoryPrivacyCatalogState(<redacted>)"


class MemoryPrivacyPolicyStore:
    __slots__ = ("_clock", "_lock", "_state")

    def __init__(self, state: MemoryPrivacyCatalogState, clock: ClockPort) -> None:
        self._state = state
        self._clock = clock
        self._lock = asyncio.Lock()

    async def seed_if_absent(self, policy: PrivacyPolicy) -> PrivacyPolicy:
        digest = _scope_digest(policy.effective_scope)
        async with self._lock:
            existing = self._state.policies.get(digest)
            if existing is not None:
                if existing.policy != policy:
                    raise ValueError("privacy_policy_seed_conflict")
                return existing.policy
            self._state.generation += 1
            self._state.policies[digest] = _PolicyRow(policy, self._state.generation)
        return policy

    async def effective_policy(self, scope: AuthorizationScope) -> EffectivePrivacyPolicy:
        eligible = [
            row
            for row in self._state.policies.values()
            if row.policy.effective_scope.contains(scope)
        ]
        if not eligible:
            raise ValueError("privacy_policy_missing")
        # ADR-009 / protocol: intersection of every containing current row — not rank-max alone.
        rank = {
            AuthorizationScopeKind.MACHINE: 0,
            AuthorizationScopeKind.WORKSPACE: 1,
            AuthorizationScopeKind.TASK: 2,
            AuthorizationScopeKind.REQUEST: 3,
        }
        ordered = sorted(
            eligible,
            key=lambda item: (rank[item.policy.effective_scope.kind], item.generation),
        )
        composed = ordered[0].policy
        for row in ordered[1:]:
            composed = composed.meet(row.policy)
        # Most-specific row's own generation: it is the CAS token the transition path compares
        # against the exact stored row. See the matching note in CatalogPrivacyPolicyStore.
        generation = ordered[-1].generation
        return EffectivePrivacyPolicy(composed, generation, composed.policy_digest)

    async def repository_authority(self, scope: AuthorizationScope) -> RepositoryPrivacyAuthority:
        if scope.kind is AuthorizationScopeKind.MACHINE or scope.workspace_ref_commitment is None:
            raise ValueError("repository_privacy_scope_required")
        rank = {
            AuthorizationScopeKind.MACHINE: 0,
            AuthorizationScopeKind.WORKSPACE: 1,
            AuthorizationScopeKind.TASK: 2,
            AuthorizationScopeKind.REQUEST: 3,
        }
        eligible = sorted(
            (
                row
                for row in self._state.policies.values()
                if row.policy.effective_scope.contains(scope)
            ),
            key=lambda row: (rank[row.policy.effective_scope.kind], row.generation),
        )
        if not eligible:
            raise ValueError("privacy_policy_missing")
        composed = eligible[0].policy
        for row in eligible[1:]:
            composed = composed.meet(row.policy)
        exact = next(
            (
                row
                for row in eligible
                if row.policy.effective_scope.kind is AuthorizationScopeKind.WORKSPACE
                and row.policy.effective_scope.workspace_ref_commitment
                == scope.workspace_ref_commitment
            ),
            None,
        )
        if self._state.first_repository_carry_forward_state is None:
            machine = next(
                (
                    row
                    for row in eligible
                    if row.policy.effective_scope.kind is AuthorizationScopeKind.MACHINE
                ),
                None,
            )
            self._state.first_repository_carry_forward_state = (
                "not_applicable"
                if machine is None
                or not machine.policy.network_egress_permitted
                or self._state.legacy_route_entitlements
                else "available"
            )
            self._state.migration_frontier_policy = None if machine is None else machine.policy
        first_state = self._state.first_repository_carry_forward_state
        machine_policy = next(
            (
                row.policy
                for row in eligible
                if row.policy.effective_scope.kind is AuthorizationScopeKind.MACHINE
            ),
            None,
        )
        if (
            machine_policy is None
            or not machine_policy.network_egress_permitted
            or self._state.migration_frontier_policy is None
            or not self._state.migration_frontier_policy.network_egress_permitted
        ):
            migration_state = "not_applicable"
        elif exact is not None:
            migration_state = (
                "consumed"
                if scope.workspace_ref_commitment
                == self._state.first_repository_carry_forward_commitment
                or scope.workspace_ref_commitment
                in self._state.consumed_legacy_repository_commitments
                else "not_applicable"
            )
        elif self._state.legacy_route_entitlements:
            migration_state = "legacy_route_available"
        elif first_state == "available":
            migration_state = "first_repository_available"
        else:
            migration_state = "not_applicable"
        ancestors = tuple(
            PrivacyAuthorityAncestor(
                row.policy.effective_scope, row.generation, row.policy.policy_digest
            )
            for row in eligible
        )
        grant_state = "granted" if exact is not None else "missing"
        authority_digest = canonical_digest(
            {
                "ancestors": [
                    {
                        "generation": item.generation,
                        "policy_digest": item.policy_digest,
                        "scope": _json(item.scope),
                    }
                    for item in ancestors
                ],
                "authority_mode": "repository_grants",
                "grant_state": grant_state,
                "migration_state": migration_state,
                "repository_privacy_commitment": scope.workspace_ref_commitment,
            }
        )
        return RepositoryPrivacyAuthority(
            scope,
            EffectivePrivacyPolicy(composed, eligible[-1].generation, composed.policy_digest),
            scope.workspace_ref_commitment,
            grant_state,
            migration_state,
            authority_digest,
            ancestors,
            None if exact is None else exact.generation,
            None if exact is None else exact.policy.policy_digest,
            None if exact is None else exact.policy,
            machine_policy,
            (
                tuple(self._state.legacy_route_entitlements.values())
                if migration_state == "legacy_route_available"
                else (
                    (self._state.migration_frontier_policy,)
                    if migration_state == "first_repository_available"
                    and self._state.migration_frontier_policy is not None
                    else ()
                )
            ),
        )

    async def carry_forward_repository_authority(
        self,
        scope: AuthorizationScope,
        *,
        task_id: str | None = None,
        route_identity_digest: str | None = None,
    ) -> RepositoryPrivacyAuthority:
        if scope.kind is not AuthorizationScopeKind.WORKSPACE:
            raise ValueError("repository_privacy_scope_required")
        if (task_id is None) != (route_identity_digest is None):
            raise ValueError("repository_privacy_route_binding_invalid")
        current = await self.repository_authority(scope)
        if current.grant_state == "granted":
            return current
        async with self._lock:
            machine = next(
                (
                    row
                    for row in self._state.policies.values()
                    if row.policy.effective_scope.kind is AuthorizationScopeKind.MACHINE
                    and row.policy.effective_scope.installation_id == scope.installation_id
                ),
                None,
            )
            if machine is None or not machine.policy.network_egress_permitted:
                raise ValueError("repository_privacy_migration_unavailable")
            if task_id is None:
                if (
                    self._state.first_repository_carry_forward_state != "available"
                    or self._state.legacy_route_entitlements
                ):
                    raise ValueError("repository_privacy_migration_unavailable")
                frontier = self._state.migration_frontier_policy
                entitlement: tuple[str, str] | None = None
            else:
                entitlement = (task_id, cast(str, route_identity_digest))
                if entitlement not in self._state.legacy_route_entitlements:
                    raise ValueError("repository_privacy_migration_unavailable")
                frontier = self._state.legacy_route_entitlements[entitlement]
            if frontier is None:
                raise ValueError("privacy_authority_state_corrupt")
            if not frontier.network_egress_permitted:
                raise ValueError("repository_privacy_migration_unavailable")
            policy = _policy_for_repository(frontier.meet(machine.policy), scope)
            self._state.generation += 1
            self._state.policies[_scope_digest(scope)] = _PolicyRow(policy, self._state.generation)
            if entitlement is None:
                self._state.first_repository_carry_forward_state = "consumed"
                self._state.first_repository_carry_forward_commitment = cast(
                    str, scope.workspace_ref_commitment
                )
            else:
                del self._state.legacy_route_entitlements[entitlement]
                self._state.consumed_legacy_repository_commitments.add(
                    cast(str, scope.workspace_ref_commitment)
                )
        return await self.repository_authority(scope)

    async def insert_repository_tightening(
        self,
        scope: AuthorizationScope,
        policy: PrivacyPolicy,
        expected_authority_digest: str,
    ) -> PolicyCommitResult:
        if scope.kind is not AuthorizationScopeKind.WORKSPACE or policy.effective_scope != scope:
            raise ValueError("repository_privacy_scope_required")
        async with self._lock:
            authority = await self.repository_authority(scope)
            if (
                authority.authority_digest != expected_authority_digest
                or authority.grant_state != "missing"
            ):
                raise ValueError("privacy_policy_stale")
            self._state.generation += 1
            self._state.policies[_scope_digest(scope)] = _PolicyRow(policy, self._state.generation)
            generation = self._state.generation
        return PolicyCommitResult(policy, generation, 0, 0)

    async def prepare_transition(
        self, proposal: PolicyTransitionProposal
    ) -> PreparedPolicyTransition:
        if proposal.privacy_proposal_id is None or proposal.expected_policy_digest is None:
            raise ValueError("privacy_policy_proposal_identity_missing")
        members = proposal.members or (
            PolicyTransitionMember(
                "replace",
                proposal.scope,
                proposal.proposed_policy,
                proposal.expected_generation,
                proposal.expected_policy_digest,
            ),
        )
        if proposal.authority_digest is not None:
            authority = await self.repository_authority(proposal.scope)
            if authority.authority_digest != proposal.authority_digest:
                raise ValueError("privacy_policy_stale")
        for member in members:
            current = self._state.policies.get(_scope_digest(member.scope))
            if member.action == "insert":
                if current is not None:
                    raise ValueError("privacy_policy_stale")
            elif current is None or (
                current.generation,
                current.policy.policy_digest,
            ) != (member.expected_generation, member.expected_policy_digest):
                raise ValueError("privacy_policy_stale")
        exact_diff = canonical_digest(
            {
                "authority_digest": proposal.authority_digest,
                "members": [
                    {
                        "action": member.action,
                        "candidate_policy_digest": member.candidate_policy.policy_digest,
                        "expected_generation": member.expected_generation,
                        "expected_policy_digest": member.expected_policy_digest,
                        "scope": _json(member.scope),
                    }
                    for member in members
                ],
            }
        )
        prepared_digest = canonical_digest(
            {
                "authority_digest": proposal.authority_digest,
                "diff_digest": exact_diff,
                "proposal_digest": proposal.proposal_digest,
                "proposal_id": proposal.privacy_proposal_id,
            }
        )
        prepared = PreparedPolicyTransition(proposal, prepared_digest, exact_diff, True)
        async with self._lock:
            existing = self._state.transitions.get(proposal.privacy_proposal_id)
            if existing is not None:
                if existing.state == "pending" and existing.prepared == prepared:
                    return prepared
                raise ValueError("privacy_policy_transition_conflict")
            self._state.transitions[proposal.privacy_proposal_id] = _MemoryTransition(prepared)
        return prepared

    async def load_pending_transition(self, proposal_id: str) -> PreparedPolicyTransition:
        row = self._state.transitions.get(proposal_id)
        if row is None or row.state != "pending":
            raise ValueError("privacy_policy_transition_unavailable")
        return row.prepared

    async def load_transition(self, proposal_id: str) -> PreparedPolicyTransition:
        row = self._state.transitions.get(proposal_id)
        if row is None or row.state not in {"pending", "committed", "denied"}:
            raise ValueError("privacy_policy_transition_unavailable")
        return row.prepared

    async def commit_transition(
        self, prepared: PreparedPolicyTransition, decision: HumanPolicyDecision
    ) -> PolicyCommitResult:
        proposal = prepared.proposal
        proposal_id = proposal.privacy_proposal_id
        if proposal_id is None or decision.prepared_digest != prepared.prepared_digest:
            raise ValueError("privacy_policy_decision_mismatch")
        decision_digest = canonical_digest(
            {
                "approved": decision.approved,
                "authority_commitment": decision.authority_commitment,
                "prepared_digest": decision.prepared_digest,
                "proposal_id": proposal_id,
            }
        )
        async with self._lock:
            stored = self._state.transitions.get(proposal_id)
            if stored is None or stored.prepared != prepared:
                raise ValueError("privacy_policy_transition_unavailable")
            if stored.state in {"committed", "denied"}:
                if stored.decision_digest != decision_digest or stored.result is None:
                    raise ValueError("privacy_policy_decision_mismatch")
                return replace(stored.result, replayed=True)
            if stored.state == "expired":
                raise ValueError("privacy_policy_decision_expired")
            if stored.state == "stale":
                raise ValueError("privacy_policy_stale")
            if decision.decided_at >= proposal.expires_at:
                self._state.transitions[proposal_id] = _MemoryTransition(prepared, "expired")
                raise ValueError("privacy_policy_decision_expired")
            members = proposal.members or (
                PolicyTransitionMember(
                    "replace",
                    proposal.scope,
                    proposal.proposed_policy,
                    proposal.expected_generation,
                    proposal.expected_policy_digest,
                ),
            )
            if proposal.authority_digest is not None:
                authority = await self.repository_authority(proposal.scope)
                if authority.authority_digest != proposal.authority_digest:
                    self._state.transitions[proposal_id] = _MemoryTransition(prepared, "stale")
                    raise ValueError("privacy_policy_stale")
            for member in members:
                current = self._state.policies.get(_scope_digest(member.scope))
                valid = (
                    current is None
                    if member.action == "insert"
                    else current is not None
                    and (current.generation, current.policy.policy_digest)
                    == (member.expected_generation, member.expected_policy_digest)
                )
                if not valid:
                    self._state.transitions[proposal_id] = _MemoryTransition(prepared, "stale")
                    raise ValueError("privacy_policy_stale")
            if not decision.approved:
                current = await self.effective_policy(proposal.scope)
                result = PolicyCommitResult(current.policy, current.generation, 0, 0)
                self._state.transitions[proposal_id] = _MemoryTransition(
                    prepared, "denied", decision_digest, result, decision.decided_at
                )
                return result
            result: PolicyCommitResult | None = None
            for member in members:
                self._state.generation += 1
                self._state.policies[_scope_digest(member.scope)] = _PolicyRow(
                    member.candidate_policy, self._state.generation
                )
                result = PolicyCommitResult(member.candidate_policy, self._state.generation, 0, 0)
            if result is None:
                raise ValueError("privacy_policy_transition_base_missing")
            self._state.transitions[proposal_id] = _MemoryTransition(
                prepared, "committed", decision_digest, result, decision.decided_at
            )
        return result

    async def tighten(
        self, scope: AuthorizationScope, overlay: PolicyOverlay, expected_policy_digest: str
    ) -> PolicyCommitResult:
        async with self._lock:
            current = self._state.policies.get(_scope_digest(scope))
            if current is None or current.policy.policy_digest != expected_policy_digest:
                raise ValueError("privacy_policy_stale")
            self._state.generation += 1
            self._state.policies[_scope_digest(scope)] = _PolicyRow(
                overlay.candidate_policy, self._state.generation
            )
        return PolicyCommitResult(overlay.candidate_policy, self._state.generation, 0, 0)

    async def watch_generation(self) -> int:
        return self._state.generation


def _receipt_view(receipt: LocalDisclosureReceipt | EgressReceipt) -> PrivacyReceiptView:
    if receipt.schema_version == "1.0.0":
        # SQLite's released 1.0 bytes do not carry the additive scan-stage fields. Match that
        # reader contract in memory instead of returning a misleading PREPARED_CASE default.
        receipt = replace(
            receipt,
            secret_scan=replace(
                receipt.secret_scan,
                stage=ReceiptSecretScanStage.LEGACY_UNKNOWN,
                not_run_reason=None,
            ),
        )
    if isinstance(receipt, LocalDisclosureReceipt):
        return LocalDisclosureReceiptView("local_disclosure", receipt)
    return NetworkEgressReceiptView("network_egress", receipt)


def _receipt_matches(
    receipt: LocalDisclosureReceipt | EgressReceipt, query: PrivacyReceiptQuery
) -> bool:
    """Apply every query filter the SQLite catalog applies, over the same receipt fields."""

    if query.receipt_id is not None and receipt.receipt_id != query.receipt_id:
        return False
    if query.outcome is not None and receipt.outcome is not query.outcome:
        return False
    if query.policy_version is not None and receipt.policy.version != query.policy_version:
        return False
    if query.scope_kind is not None and receipt.scope.kind is not query.scope_kind:
        return False
    if query.finished_at_from is not None and receipt.finished_at < query.finished_at_from:
        return False
    if query.finished_at_through is not None and receipt.finished_at > query.finished_at_through:
        return False
    if isinstance(receipt, LocalDisclosureReceipt):
        return (
            (query.local_sink is None or receipt.sink is query.local_sink)
            and query.channel is None
            and query.provider_id is None
            and query.endpoint_profile_id is None
        )
    if query.local_sink is not None:
        return False
    if query.channel is not None and receipt.channel is not query.channel:
        return False
    destination = receipt.destination
    binding = destination if isinstance(destination, ProviderBinding) else None
    if query.provider_id is not None and (
        binding is None or binding.provider_id != query.provider_id
    ):
        return False
    return query.endpoint_profile_id is None or (
        binding is not None and binding.endpoint_profile_id == query.endpoint_profile_id
    )


class MemoryPrivacyAudit:
    __slots__ = ("_clock", "_key", "_lock", "_objects", "_state")

    def __init__(
        self,
        state: MemoryPrivacyCatalogState,
        objects: ObjectStorePort,
        audit_key: MacKeyHandle,
        clock: ClockPort,
    ) -> None:
        self._state = state
        self._objects = objects
        self._key = audit_key
        self._clock = clock
        self._lock = asyncio.Lock()

    async def complete_agent_projection(
        self, request: AgentProjectionRequest, receipt: LocalDisclosureReceipt
    ) -> CompletedAgentProjection:
        control = _mac(self._key, _CONTROL_DOMAIN, request.control_request_canonical)
        internal = _mac(self._key, _INTERNAL_RESULT_DOMAIN, request.internal_result_canonical)
        projection = _mac(self._key, _PROJECTION_DOMAIN, request.projection_canonical)
        del control
        subject = AgentProjectionAuditSubject(
            request.privacy_proposal_id,
            request.projection_request_id,
            request.rpc_id,
            request.method,
            request.service_instance_id,
            request.service_generation,
            request.original_request_id,
            request.scope,
            request.task_id,
            request.route_identity_digest,
            request.policy_id,
            request.policy_version,
            request.policy_digest,
            request.sink,
            request.provenance,
            internal,
            projection,
            request.field_decisions,
            request.candidate_count,
            request.approved_count,
            request.omitted_count,
            request.finished_at,
        )
        now = self._clock.now_utc()
        reservation = PrivacyAuditReservation(
            request.privacy_proposal_id,
            request.projection_request_id,
            projection,
            "local_disclosure_completed",
            request.policy_generation,
            now,
        )
        row = _AuditRow(reservation, subject, "local_disclosure_completed", receipt)
        async with self._lock:
            existing = self._state.audit.get(request.privacy_proposal_id)
            if existing is not None and existing != row:
                raise ValueError("privacy_projection_replay_conflict")
            self._state.audit[request.privacy_proposal_id] = row
        return CompletedAgentProjection(subject, reservation)

    async def prepare_disclosure_proposal(
        self, request: DisclosureProposalRequest
    ) -> PreparedDisclosureReservation:
        now = self._clock.now_utc()
        route = self._state.routes.get(request.task_id)
        if route is None:
            raise ValueError("privacy_audit_route_unavailable")
        value: dict[str, JsonValue] = {
            "approved_categories": [item.value for item in request.minimized.approved_categories],
            "blocked_categories": [item.value for item in request.minimized.blocked_categories],
            "expires_at": request.expires_at.isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            "policy_digest": request.policy_digest,
            "prepared_bytes_base64": base64.b64encode(request.minimized.prepared_bytes).decode(
                "ascii"
            ),
            "prepared_case_digest": request.minimized.case_digest,
            "privacy_proposal_id": request.privacy_proposal_id,
            "purpose": request.purpose,
            "request_id": request.request_id,
            "schema": "yoetz.disclosure-proposal/1",
            "scope": _json(request.scope),
            "source_item_digests": list(request.minimized.source_item_digests),
            "included_item_ids": list(request.minimized.included_item_ids),
            "transformation_summary": [
                list(item) for item in request.minimized.transformation_summary
            ],
            "withheld_item_ids": list(request.minimized.withheld_item_ids),
            "scanner_registry_version": request.minimized.scanner_registry_version,
            "scanner_profile_digest": request.minimized.scanner_profile_digest,
            "route_identity_digest": route,
            # PL2-1: written only when present, so older proposals keep their exact bytes.
            **(
                {
                    "redacted_values": [
                        cast(JsonValue, entry.as_wire())
                        for entry in request.minimized.redacted_values
                    ]
                }
                if request.minimized.redacted_values
                else {}
            ),
        }
        body = canonical_encode(value)
        commitment = _mac(self._key, _PROPOSAL_DOMAIN, body)
        staged = await self._objects.stage(
            ObjectSource(data=body),
            ObjectMetadata(
                ObjectKind.PRIVACY_AUDIT,
                "application/vnd.yoetz.privacy-disclosure+json",
                request.task_id,
                now,
            ),
        )
        ref = await self._objects.finalize(staged)
        proposal = DisclosureProposal(
            request.privacy_proposal_id,
            request.request_id,
            request.task_id,
            request.minimized.source_item_digests,
            request.minimized.prepared_bytes,
            request.minimized.approved_categories,
            request.minimized.blocked_categories,
            request.minimized.transformation_summary,
            request.minimized.case_digest,
            request.provider_binding,
            request.local_sink,
            request.purpose,
            request.scope,
            request.policy_version,
            request.policy_digest,
            request.max_bytes,
            request.max_tokens,
            request.expires_at,
            commitment,
            request.minimized.withheld_item_ids,
            request.minimized.scanner_registry_version,
            request.minimized.scanner_profile_digest,
            request.minimized.included_item_ids,
            route,
            request.minimized.redacted_values,
        )
        lookup = _mac(self._key, _LOOKUP_DOMAIN, canonical_encode(_json(proposal)))
        reservation = PrivacyAuditReservation(
            request.privacy_proposal_id,
            request.request_id,
            lookup,
            "reserved",
            request.policy_generation,
            now,
        )
        async with self._lock:
            if request.privacy_proposal_id in self._state.audit:
                raise ValueError("privacy_audit_reservation_conflict")
            self._state.audit[request.privacy_proposal_id] = _AuditRow(
                reservation, proposal, "reserved", object_ref=ref
            )
            self._state.root_generation[request.task_id] = (
                self._state.root_generation.get(request.task_id, 0) + 1
            )
        return PreparedDisclosureReservation(proposal, reservation)

    async def reserve(self, subject: PrivacyAuditSubject) -> PrivacyAuditReservation:
        if type(subject) is not PreDispatchAuditDecision:
            raise ValueError("privacy_audit_subject_requires_typed_prepare")
        canonical = canonical_encode(_json(subject))
        lookup = _mac(self._key, _LOOKUP_DOMAIN, canonical)
        reservation = PrivacyAuditReservation(
            subject.privacy_proposal_id,
            subject.request_id,
            lookup,
            "decision_receipt_pending",
            1,
            self._clock.now_utc(),
        )
        async with self._lock:
            self._state.audit[subject.privacy_proposal_id] = _AuditRow(
                reservation, subject, "decision_receipt_pending"
            )
        return reservation

    async def load(self, request_id: str, subject_digest: str) -> PrivacyAuditState | None:
        for row in self._state.audit.values():
            if row.reservation.request_id == request_id and (
                row.reservation.subject_digest == subject_digest
            ):
                return PrivacyAuditState(
                    row.reservation,
                    row.status,
                    row.authorization_id,
                    row.dispatch_id,
                    receipt_id=None if row.receipt is None else row.receipt.receipt_id,
                )
        return None

    async def load_disclosure_attempt(
        self, request_id: str, case_digest: str
    ) -> PrivacyAuditState | None:
        """Find one disclosure audit row by its physical request and prepared case digest."""

        if type(request_id) is not str or type(case_digest) is not str:
            raise TypeError("privacy_disclosure_attempt_lookup_invalid")
        try:
            validate_id(IdKind.REQUEST, request_id)
            validate_sha256_digest(case_digest)
        except ValueError as exc:
            raise ValueError("privacy_disclosure_attempt_lookup_invalid") from exc
        async with self._lock:
            disclosure_rows = tuple(
                row
                for row in self._state.audit.values()
                if row.reservation.request_id == request_id
                and type(row.subject) is DisclosureProposal
            )
            if len(disclosure_rows) > 1:
                raise ValueError("privacy_audit_attempt_ambiguous")
            matches = tuple(
                row
                for row in disclosure_rows
                if cast(DisclosureProposal, row.subject).prepared_case_digest == case_digest
            )
            if len(matches) > 1:
                raise ValueError("privacy_audit_attempt_ambiguous")
            if not matches:
                if disclosure_rows:
                    raise ValueError("privacy_audit_attempt_case_mismatch")
                return None
            row = matches[0]
            return PrivacyAuditState(
                row.reservation,
                row.status,
                row.authorization_id,
                row.dispatch_id,
                receipt_id=None if row.receipt is None else row.receipt.receipt_id,
            )

    async def load_started_disclosure_attempt(self, request_id: str) -> PrivacyAuditState | None:
        """Find one disclosure audit row by its physical request identity alone."""

        if type(request_id) is not str:
            raise TypeError("privacy_disclosure_attempt_lookup_invalid")
        try:
            validate_id(IdKind.REQUEST, request_id)
        except ValueError as exc:
            raise ValueError("privacy_disclosure_attempt_lookup_invalid") from exc
        async with self._lock:
            disclosure_rows = tuple(
                row
                for row in self._state.audit.values()
                if row.reservation.request_id == request_id
                and type(row.subject) is DisclosureProposal
            )
            if len(disclosure_rows) > 1:
                raise ValueError("privacy_audit_attempt_ambiguous")
            if not disclosure_rows:
                return None
            row = disclosure_rows[0]
            return PrivacyAuditState(
                row.reservation,
                row.status,
                row.authorization_id,
                row.dispatch_id,
                receipt_id=None if row.receipt is None else row.receipt.receipt_id,
            )

    async def load_disclosure_proposal(self, proposal_id: str) -> DisclosureProposal | None:
        async with self._lock:
            row = self._state.audit.get(proposal_id)
            if row is None or type(row.subject) is not DisclosureProposal:
                return None
            # Resume is valid only for the route that authenticated the proposal.  A stale or
            # legacy subject is unreadable; the coordinator must not reinterpret it under a new
            # active route.
            if (
                row.subject.route_identity_digest is None
                or self._state.routes.get(row.subject.task_id) != row.subject.route_identity_digest
            ):
                return None
            return row.subject

    async def load_authorization(self, authorization_id: str) -> EgressAuthorization | None:
        del authorization_id
        return None

    async def consume_local(
        self, reservation_id: str, approved_case_digest: str, now: datetime
    ) -> ConsumedLocalDisclosure:
        async with self._lock:
            row = self._state.audit.get(reservation_id)
            if (
                row is None
                or row.status != "reserved"
                or type(row.subject) is not DisclosureProposal
            ):
                raise ValueError("privacy_local_reservation_unavailable")
            if row.subject.prepared_case_digest != approved_case_digest:
                raise ValueError("privacy_local_case_digest_mismatch")
            if row.subject.expires_at <= now:
                raise ValueError("privacy_local_reservation_expired")
            self._state.audit[reservation_id] = _AuditRow(
                row.reservation,
                row.subject,
                "local_disclosure_pending",
                object_ref=row.object_ref,
                consumed_digest=approved_case_digest,
            )
        assert row.subject.local_sink is not None
        return ConsumedLocalDisclosure(
            reservation_id, approved_case_digest, row.subject.local_sink, now
        )

    async def complete_local_disclosure(
        self, reservation_id: str, receipt: LocalDisclosureReceipt
    ) -> None:
        await self._complete(
            reservation_id, receipt, "local_disclosure_pending", "local_disclosure_completed"
        )

    async def complete_decision(
        self, reservation_id: str, receipt: EgressReceipt | LocalDisclosureReceipt
    ) -> None:
        await self._complete(
            reservation_id, receipt, "decision_receipt_pending", "decision_completed"
        )

    async def _complete(
        self,
        reservation_id: str,
        receipt: LocalDisclosureReceipt | EgressReceipt,
        expected: str,
        terminal: str,
    ) -> None:
        async with self._lock:
            row = self._state.audit.get(reservation_id)
            if row is None or row.status != expected:
                raise ValueError("privacy_audit_state_conflict")
            self._state.audit[reservation_id] = _AuditRow(
                row.reservation,
                row.subject,
                terminal,
                receipt,
                row.object_ref,
                row.consumed_digest,
                row.authorization_id,
                row.dispatch_id,
            )

    async def get_receipt(
        self, receipt_id: str, audience: PrivacyReceiptAudience
    ) -> PrivacyReceiptView | None:
        if audience is not PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL:
            raise ValueError("privacy_receipt_audience_invalid")
        for row in self._state.audit.values():
            if row.receipt is not None and row.receipt.receipt_id == receipt_id:
                return _receipt_view(row.receipt)
        return None

    async def list_pending_disclosures(
        self, audience: PrivacyReceiptAudience
    ) -> PendingDisclosurePage:
        if audience is not PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL:
            raise ValueError("privacy_receipt_audience_invalid")
        async with self._lock:
            now = self._clock.now_utc()
            entries = tuple(
                PendingDisclosureEntry(
                    row.subject.privacy_proposal_id,
                    row.subject.task_id,
                    row.subject.expires_at,
                )
                for row in self._state.audit.values()
                if type(row.subject) is DisclosureProposal
                and row.status in {"awaiting_human", "reserved"}
                and row.subject.expires_at > now
            )
        ordered = tuple(sorted(entries, key=lambda entry: (entry.expires_at, entry.pending_id)))
        return PendingDisclosurePage(len(self._state.audit) + 1, ordered[:100])

    async def list_receipts(
        self, query: PrivacyReceiptQuery, audience: PrivacyReceiptAudience
    ) -> PrivacyReceiptPage:
        if audience is not PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL:
            raise ValueError("privacy_receipt_audience_invalid")
        values = [
            _receipt_view(row.receipt)
            for row in self._state.audit.values()
            if row.receipt is not None and _receipt_matches(row.receipt, query)
        ]
        values.sort(
            key=lambda view: (view.receipt.finished_at, view.receipt.receipt_id), reverse=True
        )
        query_identity: dict[str, JsonValue] = {
            "limit": query.limit,
            "receipt_id": query.receipt_id,
        }
        start = 0
        if query.cursor is not None:
            payload = self._decode_cursor(query.cursor)
            if payload.get("query_digest") != canonical_digest(query_identity):
                raise PrivacyReceiptCursorInvalid("privacy_receipt_cursor_query_mismatch")
            after = payload.get("after_id")
            if type(after) is not str:
                raise PrivacyReceiptCursorInvalid("privacy_receipt_cursor_invalid")
            start = next(
                (
                    index + 1
                    for index, view in enumerate(values)
                    if view.receipt.receipt_id == after
                ),
                len(values),
            )
        selected = values[start : start + query.limit]
        next_cursor = None
        if start + query.limit < len(values) and selected:
            next_cursor = self._encode_cursor(
                {
                    "after_id": selected[-1].receipt.receipt_id,
                    "query_digest": canonical_digest(query_identity),
                    "version": 1,
                }
            )
        return PrivacyReceiptPage(
            max(1, self._state.generation + len(self._state.audit)), tuple(selected), next_cursor
        )

    def _encode_cursor(self, payload: dict[str, JsonValue]) -> str:
        body = canonical_encode(payload)
        envelope = canonical_encode(
            {
                "body": base64.urlsafe_b64encode(body).decode("ascii").rstrip("="),
                "mac": _mac(self._key, _CURSOR_DOMAIN, body),
            }
        )
        return base64.urlsafe_b64encode(envelope).decode("ascii").rstrip("=")

    def _decode_cursor(self, cursor: str) -> dict[str, JsonValue]:
        from finishup.protocol.canonical import strict_json_parse

        try:
            envelope = cast(
                dict[str, JsonValue],
                strict_json_parse(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))),
            )
            body_text = cast(str, envelope["body"])
            body = base64.urlsafe_b64decode(body_text + "=" * (-len(body_text) % 4))
            if not hmac.compare_digest(
                cast(str, envelope["mac"]), _mac(self._key, _CURSOR_DOMAIN, body)
            ):
                raise ValueError
            return cast(dict[str, JsonValue], strict_json_parse(body))
        except (KeyError, TypeError, ValueError) as exc:
            raise PrivacyReceiptCursorInvalid("privacy_receipt_cursor_invalid") from exc

    async def live_object_roots(
        self, task_id: str, route_identity_digest: str
    ) -> PrivacyAuditObjectRoots:
        if self._state.routes.get(task_id) != route_identity_digest:
            raise ValueError("privacy_audit_route_unavailable")
        refs = tuple(
            sorted(
                (
                    row.object_ref
                    for row in self._state.audit.values()
                    if row.object_ref is not None and row.object_ref.metadata.task_id == task_id
                ),
                key=lambda ref: ref.object_id.encode(),
            )
        )
        return PrivacyAuditObjectRoots(
            task_id,
            route_identity_digest,
            self._state.root_generation.get(task_id, 0),
            refs,
            canonical_digest([_json(ref) for ref in refs]),
        )

    async def revoke_policy_generation(self, generation: int, reason: str) -> int:
        del generation, reason
        return 0

    async def mark_awaiting_human(self, reservation_id: str) -> PrivacyAuditState:
        async with self._lock:
            row = self._state.audit.get(reservation_id)
            if row is None or row.status != "reserved":
                raise ValueError("privacy_audit_state_conflict")
            self._state.audit[reservation_id] = _AuditRow(
                row.reservation, row.subject, "awaiting_human", object_ref=row.object_ref
            )
            return PrivacyAuditState(
                PrivacyAuditReservation(
                    row.reservation.privacy_proposal_id,
                    row.reservation.request_id,
                    row.reservation.subject_digest,
                    "awaiting_human",
                    row.reservation.policy_generation,
                    row.reservation.reserved_at,
                ),
                "awaiting_human",
            )

    async def record_human_decision(
        self, reservation_id: str, decision: HumanPrivacyDecision
    ) -> PrivacyAuditState:
        del reservation_id, decision
        raise ValueError("network_privacy_authority_unavailable_until_b8")

    async def authorize(
        self, reservation_id: str, approved_case_digest: str, now: datetime
    ) -> EgressAuthorization:
        del reservation_id, approved_case_digest, now
        raise ValueError("network_privacy_authority_unavailable_until_b8")

    async def consume(
        self,
        authorization_id: str,
        dispatch_id: str,
        now: datetime,
        *,
        owed_receipt: EgressReceipt | None = None,
    ) -> ConsumedAuthorization:
        del authorization_id, dispatch_id, now, owed_receipt
        raise ValueError("network_privacy_dispatch_unavailable_until_b8")

    async def complete_egress(self, dispatch_id: str, receipt: EgressReceipt) -> None:
        del dispatch_id, receipt
        raise ValueError("network_privacy_dispatch_unavailable_until_b8")

    async def reconcile_started_attempts(self, consumed_before: datetime, limit: int) -> int:
        """No memory-adapter row reaches ``receipt_pending``: network dispatch never admits here."""

        del consumed_before, limit
        return 0
