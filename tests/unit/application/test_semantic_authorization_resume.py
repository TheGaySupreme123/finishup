"""Failure-matrix coverage for resuming one-use AI-powered review disclosure authority."""

from __future__ import annotations

import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from builders.privacy_policies import minimal_external_policy
from yoetz.adapters.privacy.local_enforcer import SecretScanRuleset
from yoetz.application.egress import (
    PrivacyCoordinator,
    SemanticEgressAttemptUnknown,
    SemanticEgressAwaitingHuman,
    SemanticEgressBlocked,
    SemanticEgressSuccess,
)
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ConsentSource,
    DisclosureProposal,
    ForbiddenDataKind,
    PrivacyOutcome,
    PrivacyProfile,
    PrivacyReason,
    ProviderBinding,
)
from yoetz.ports.clock import ClockPort
from yoetz.ports.ids import IdPort
from yoetz.ports.privacy import (
    EffectivePrivacyPolicy,
    HumanAuthorityCapability,
    OutboundGatewayPort,
    PrivacyAuditPort,
    PrivacyAuditReservation,
    PrivacyAuditState,
    PrivacyClassifierPort,
    PrivacyPolicyStorePort,
    RepositoryPrivacyAuthority,
)
from yoetz.ports.semantic import Deadline
from yoetz.protocol.ids import IdKind

_NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
_INSTALLATION = "ins_54000000-0000-4000-8000-000000000001"
_TASK = "tsk_54000000-0000-4000-8000-000000000002"
_REQUEST = "req_54000000-0000-4000-8000-000000000003"
_PROPOSAL = "ppr_54000000-0000-4000-8000-000000000004"
_WORKSPACE = "hmac-sha256:" + "5" * 64
_CASE_DIGEST = "sha256:" + "6" * 64
_AUTHORITY_DIGEST = "sha256:" + "8" * 64
_ROUTE_DIGEST = "sha256:" + "7" * 64
_SCANNER = SecretScanRuleset()


class _Clock:
    def __init__(self, now: datetime = _NOW) -> None:
        self.now = now

    def now_utc(self) -> datetime:
        return self.now

    def monotonic_seconds(self) -> float:
        return 1.0


class _Ids:
    def __init__(self) -> None:
        self.next_value = 0

    def new(self, kind: IdKind) -> str:
        self.next_value += 1
        prefix = "out_" if kind is IdKind.OUTBOUND_CASE else "egr_"
        return f"{prefix}54000000-0000-4000-8000-{self.next_value:012x}"


def _scope() -> AuthorizationScope:
    return AuthorizationScope(
        AuthorizationScopeKind.TASK,
        _INSTALLATION,
        _WORKSPACE,
        _TASK,
    )


def _binding() -> ProviderBinding:
    policy = minimal_external_policy()
    binding = next(
        channel.provider_binding
        for channel in policy.channel_policies
        if channel.provider_binding is not None
    )
    return binding


def _effective() -> EffectivePrivacyPolicy:
    base = minimal_external_policy()
    channels = tuple(
        replace(channel, preview_required=True) if channel.provider_binding is not None else channel
        for channel in base.channel_policies
    )
    policy = replace(
        base,
        profile=PrivacyProfile.CONFIRM_EVERY_REQUEST,
        effective_scope=_scope(),
        channel_policies=channels,
    )
    return EffectivePrivacyPolicy(policy, 2, policy.policy_digest)


def _proposal(*, expires_at: datetime) -> DisclosureProposal:
    policy = _effective().policy
    return DisclosureProposal(
        _PROPOSAL,
        _REQUEST,
        _TASK,
        ("sha256:" + "9" * 64,),
        b"{}",
        (),
        (),
        (),
        _CASE_DIGEST,
        _binding(),
        None,
        "semantic-review",
        _scope(),
        policy.version,
        policy.policy_digest,
        2,
        1,
        expires_at,
        "hmac-sha256:" + "a" * 64,
        (),
        _SCANNER.version,
        _SCANNER.profile_digest,
        ("excerpt-a",),
        _ROUTE_DIGEST,
    )


def test_proposals_without_persisted_scanner_identity_remain_explicitly_unknown() -> None:
    proposal = replace(
        _proposal(expires_at=_NOW + timedelta(minutes=5)),
        scanner_registry_version="unknown",
        scanner_profile_digest="sha256:" + "0" * 64,
    )
    assert proposal.scanner_registry_version == "unknown"


class _Classifier:
    def __init__(self, findings: tuple[ForbiddenDataKind, ...] = ()) -> None:
        self.findings = findings

    def scanner_identity(self) -> tuple[str, str]:
        return _SCANNER.version, _SCANNER.profile_digest

    def scan_exact_bytes(
        self, data: bytes, *, credential_heuristic: object = None
    ) -> tuple[ForbiddenDataKind, ...]:
        del data, credential_heuristic
        return self.findings


class _Audit:
    def __init__(self, status: str, proposal: DisclosureProposal) -> None:
        self.status = status
        self.proposal = proposal

    async def load(self, request_id: str, subject_digest: str) -> PrivacyAuditState | None:
        assert (request_id, subject_digest) == (_REQUEST, _CASE_DIGEST)
        reservation = PrivacyAuditReservation(
            _PROPOSAL,
            _REQUEST,
            _CASE_DIGEST,
            self.status,
            2,
            _NOW,
        )
        return PrivacyAuditState(reservation, self.status)

    async def load_disclosure_attempt(
        self, request_id: str, case_digest: str
    ) -> PrivacyAuditState | None:
        assert (request_id, case_digest) == (_REQUEST, _CASE_DIGEST)
        return await self.load(request_id, _CASE_DIGEST)

    async def load_disclosure_proposal(self, proposal_id: str) -> DisclosureProposal | None:
        assert proposal_id == _PROPOSAL
        return self.proposal


class _Policies:
    def __init__(self, *, granted: bool) -> None:
        self.granted = granted
        self.effective = _effective()

    async def effective_policy(self, scope: AuthorizationScope) -> EffectivePrivacyPolicy:
        assert scope == _scope()
        return self.effective

    async def repository_authority(self, scope: AuthorizationScope) -> RepositoryPrivacyAuthority:
        assert scope == _scope()
        policy = self.effective.policy
        grant_policy = replace(
            policy,
            effective_scope=AuthorizationScope(
                AuthorizationScopeKind.WORKSPACE,
                _INSTALLATION,
                _WORKSPACE,
            ),
        )
        return RepositoryPrivacyAuthority(
            scope,
            self.effective,
            _WORKSPACE,
            "granted" if self.granted else "missing",
            "not_applicable",
            _AUTHORITY_DIGEST,
            (),
            2 if self.granted else None,
            grant_policy.policy_digest if self.granted else None,
            grant_policy if self.granted else None,
        )


class _Gateway:
    def __init__(self) -> None:
        self.reconciliations = 0

    async def reconcile_repository_policy(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        self.reconciliations += 1
        return object()

    async def close(self) -> None:
        return None


def _coordinator(
    status: str,
    *,
    expires_at: datetime,
    granted: bool = True,
    clock: _Clock | None = None,
    proposal: DisclosureProposal | None = None,
    classifier: _Classifier | None = None,
) -> PrivacyCoordinator:
    return PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, _Policies(granted=granted)),
        cast(PrivacyClassifierPort, classifier or _Classifier()),
        cast(
            PrivacyAuditPort,
            _Audit(status, proposal or _proposal(expires_at=expires_at)),
        ),
        cast(OutboundGatewayPort, _Gateway()),
        cast(ClockPort, clock or _Clock()),
        cast(IdPort, _Ids()),
        human_authority=HumanAuthorityCapability(
            "established_passphrase",
            "sha256:" + "b" * 64,
            1,
            "passphrase",
            1,
            True,
        ),
    )


def _deadline() -> Deadline:
    return Deadline(_NOW + timedelta(minutes=10), 600.0)


@pytest.mark.anyio
@pytest.mark.parametrize("status", ("reserved", "awaiting_human"))
async def test_unanswered_or_crash_before_wait_marking_remains_nonterminal(status: str) -> None:
    coordinator = _coordinator(status, expires_at=_NOW + timedelta(minutes=5))

    result = await coordinator.resume(_REQUEST, _CASE_DIGEST, _deadline())

    assert isinstance(result, SemanticEgressAwaitingHuman)
    assert result.privacy_proposal_id == _PROPOSAL
    assert result.expires_at == _NOW + timedelta(minutes=5)


@pytest.mark.anyio
async def test_expired_wait_terminalizes_without_dispatch() -> None:
    coordinator = _coordinator(
        "awaiting_human",
        expires_at=_NOW - timedelta(seconds=1),
    )

    result = await coordinator.resume(_REQUEST, _CASE_DIGEST, _deadline())

    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.APPROVAL_EXPIRED
    assert result.reason is PrivacyReason.AUTHORIZATION_EXPIRED


@pytest.mark.anyio
@pytest.mark.parametrize(
    "proposal",
    [
        replace(
            _proposal(expires_at=_NOW + timedelta(minutes=5)),
            request_id="req_54000000-0000-4000-8000-000000000005",
        ),
        replace(
            _proposal(expires_at=_NOW + timedelta(minutes=5)),
            privacy_proposal_id="ppr_54000000-0000-4000-8000-000000000006",
        ),
    ],
)
async def test_resume_rejects_proposal_identity_mismatch(
    proposal: DisclosureProposal,
) -> None:
    coordinator = _coordinator(
        "reserved",
        expires_at=_NOW + timedelta(minutes=5),
        proposal=proposal,
    )

    result = await coordinator.resume(_REQUEST, _CASE_DIGEST, _deadline())

    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.AUDIT_FAILED
    assert result.reason is PrivacyReason.AUDIT_FAILED


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("scanner_registry_version", "scanner_profile_digest"),
    [
        ("unknown", "sha256:" + "0" * 64),
        ("observability-sensitive-content-v2", _SCANNER.profile_digest),
    ],
)
async def test_resume_rejects_stale_scanner_identity(
    scanner_registry_version: str, scanner_profile_digest: str
) -> None:
    proposal = replace(
        _proposal(expires_at=_NOW + timedelta(minutes=5)),
        scanner_registry_version=scanner_registry_version,
        scanner_profile_digest=scanner_profile_digest,
    )
    coordinator = _coordinator(
        "approved",
        expires_at=_NOW + timedelta(minutes=5),
        proposal=proposal,
    )

    result = await coordinator.resume(_REQUEST, _CASE_DIGEST, _deadline())

    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.AUDIT_FAILED
    assert result.reason is PrivacyReason.AUDIT_FAILED


@pytest.mark.anyio
async def test_resume_rejects_changed_effective_policy_even_within_limits() -> None:
    coordinator = _coordinator("approved", expires_at=_NOW + timedelta(minutes=5))
    policies = cast(_Policies, coordinator._policies)  # pyright: ignore[reportPrivateUsage]
    policies.effective = replace(
        policies.effective,
        effective_digest="sha256:" + "d" * 64,
    )

    result = await coordinator.resume(_REQUEST, _CASE_DIGEST, _deadline())

    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.BLOCKED_BY_POLICY
    assert result.reason is PrivacyReason.POLICY_DENIED


@pytest.mark.anyio
async def test_resume_rejects_proposal_without_route_identity() -> None:
    proposal = replace(
        _proposal(expires_at=_NOW + timedelta(minutes=5)),
        route_identity_digest=None,
    )
    coordinator = _coordinator(
        "approved",
        expires_at=_NOW + timedelta(minutes=5),
        proposal=proposal,
    )

    result = await coordinator.resume(_REQUEST, _CASE_DIGEST, _deadline())

    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.AUDIT_FAILED
    assert result.reason is PrivacyReason.AUDIT_FAILED


@pytest.mark.anyio
async def test_resume_rescans_persisted_bytes_before_dispatch() -> None:
    proposal = replace(
        _proposal(expires_at=_NOW + timedelta(minutes=5)),
        prepared_bytes=b'{"token":"credential"}',
    )
    coordinator = _coordinator(
        "approved",
        expires_at=_NOW + timedelta(minutes=5),
        proposal=proposal,
        classifier=_Classifier((ForbiddenDataKind.API_CREDENTIAL,)),
    )
    dispatched: list[object] = []

    async def dispatch(self: PrivacyCoordinator, *args: object, **kwargs: object) -> object:
        del self, args, kwargs
        dispatched.append(object())
        return object()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(PrivacyCoordinator, "_dispatch_approved", dispatch)
    try:
        result = await coordinator.resume(_REQUEST, _CASE_DIGEST, _deadline())
    finally:
        monkeypatch.undo()

    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.BLOCKED_FORBIDDEN_DATA
    assert result.reason is PrivacyReason.NEVER_SEND_DETECTED
    assert dispatched == []


@pytest.mark.anyio
async def test_recorded_denial_terminalizes_without_dispatch() -> None:
    coordinator = _coordinator(
        "decision_receipt_pending",
        expires_at=_NOW + timedelta(minutes=5),
    )

    result = await coordinator.resume(_REQUEST, _CASE_DIGEST, _deadline())

    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.HUMAN_DENIED
    assert result.reason is PrivacyReason.HUMAN_DENIED


@pytest.mark.anyio
async def test_stale_repository_authority_fails_closed_before_dispatch() -> None:
    coordinator = _coordinator(
        "approved",
        expires_at=_NOW + timedelta(minutes=5),
        granted=False,
    )

    result = await coordinator.resume(_REQUEST, _CASE_DIGEST, _deadline())

    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.BLOCKED_BY_POLICY
    assert result.reason is PrivacyReason.SCOPE_MISMATCH


@pytest.mark.anyio
async def test_approved_resume_preserves_per_request_human_consent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator = _coordinator(
        "approved",
        expires_at=_NOW + timedelta(minutes=5),
    )
    captured: list[ConsentSource] = []

    async def dispatch(self: PrivacyCoordinator, *args: object, **kwargs: object) -> object:
        del self, kwargs
        captured.append(cast(ConsentSource, args[4]))
        return object()

    monkeypatch.setattr(PrivacyCoordinator, "_dispatch_approved", dispatch)

    result = await coordinator.resume(_REQUEST, _CASE_DIGEST, _deadline())

    assert result is not None
    assert captured == [ConsentSource.PER_REQUEST_LOCAL_HUMAN]


@pytest.mark.anyio
async def test_consumed_attempt_recovery_is_terminal_unknown_without_dispatch() -> None:
    coordinator = _coordinator(
        "receipt_pending",
        expires_at=_NOW + timedelta(minutes=5),
    )

    result = await coordinator.recover_started_attempt(_REQUEST, _CASE_DIGEST, _deadline())

    assert isinstance(result, SemanticEgressAttemptUnknown)
    assert result.request_id == _REQUEST
    assert result.privacy_proposal_id == _PROPOSAL


@pytest.mark.anyio
async def test_proposal_read_failure_does_not_turn_recovery_ids_into_an_empty_tuple() -> None:
    """Unreadable proposal state must remain an explicit recovery failure."""

    coordinator = _coordinator(
        "receipt_pending",
        expires_at=_NOW + timedelta(minutes=5),
    )
    audit = cast(_Audit, coordinator._audit)  # pyright: ignore[reportPrivateUsage]

    async def unreadable(_proposal_id: str) -> DisclosureProposal | None:
        raise RuntimeError("proposal_store_unavailable")

    audit.load_disclosure_proposal = unreadable  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="proposal_store_unavailable"):
        await coordinator.recover_started_attempt(_REQUEST, _CASE_DIGEST, _deadline())


@pytest.mark.anyio
async def test_missing_proposal_does_not_look_like_a_clean_unknown_recovery() -> None:
    coordinator = _coordinator(
        "receipt_pending",
        expires_at=_NOW + timedelta(minutes=5),
    )
    audit = cast(_Audit, coordinator._audit)  # pyright: ignore[reportPrivateUsage]

    async def missing(_proposal_id: str) -> DisclosureProposal | None:
        return None

    audit.load_disclosure_proposal = missing  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="privacy_audit_proposal_unavailable"):
        await coordinator.recover_started_attempt(_REQUEST, _CASE_DIGEST, _deadline())


def _packet_with_excerpts(count: int) -> bytes:
    from yoetz.protocol.canonical import JsonValue, canonical_encode

    rows = [
        {"content_bytes": 32, "item_id": f"excerpt-{index:03d}", "section": "excerpt"}
        for index in range(count)
    ]
    return canonical_encode(
        cast(JsonValue, {"items": rows, "schema": "yoetz.review-packet-case/1"})
    )


_SMALL_PACKET = b'{"p":"' + b"x" * 2_048 + b'"}'


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("prepared", "max_bytes", "max_tokens", "local"),
    [
        (_packet_with_excerpts(17), 262_144, 4_096, False),
        (_SMALL_PACKET, 1_024, 4_096, False),
        (_SMALL_PACKET, 262_144, 100, False),
        (_packet_with_excerpts(17), 262_144, 4_096, True),
    ],
    ids=["over_excerpt_count", "over_channel_bytes", "over_channel_tokens", "local_model"],
)
async def test_resume_rechecks_the_current_limits_before_dispatch(
    prepared: bytes,
    max_bytes: int,
    max_tokens: int,
    local: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #907 Phase 1b: a stored proposal answers to the policy in force at resume."""

    from yoetz.domain.privacy import DataClass, LocalDisclosureSink
    from yoetz.protocol.models import DataCategory

    proposal = replace(
        _proposal(expires_at=_NOW + timedelta(minutes=5)),
        prepared_bytes=prepared,
        max_tokens=(len(prepared) + 3) // 4,
    )
    current = _effective()
    narrowed = replace(
        current.policy,
        channel_policies=tuple(
            replace(channel, max_bytes=max_bytes, max_tokens=max_tokens)
            if channel.provider_binding is not None
            else channel
            for channel in current.policy.channel_policies
        ),
    )
    if local:
        proposal = replace(
            proposal, provider_binding=None, local_sink=LocalDisclosureSink.LOCAL_MODEL
        )
        narrowed = replace(
            narrowed,
            local_model_enabled=True,
            local_model_binding=ProviderBinding(
                "local-model", "test-model", "local-model-af-unix", "1.0.0", "local_af_unix"
            ),
            local_model_categories=(DataCategory.BOUNDED_STRUCTURAL_METADATA,),
            local_model_data_classes=(DataClass.PUBLIC_STRUCTURAL,),
        )
    monkeypatch.setattr(
        sys.modules[__name__],
        "_effective",
        lambda: EffectivePrivacyPolicy(narrowed, current.generation, current.effective_digest),
    )
    coordinator = _coordinator(
        "approved", expires_at=_NOW + timedelta(minutes=5), proposal=proposal
    )
    dispatched: list[object] = []

    async def dispatch(self: PrivacyCoordinator, *args: object, **kwargs: object) -> object:
        del self, kwargs
        dispatched.append(args)
        return object()

    monkeypatch.setattr(PrivacyCoordinator, "_dispatch_approved", dispatch)

    result = await coordinator.resume(_REQUEST, _CASE_DIGEST, _deadline())

    assert isinstance(result, SemanticEgressBlocked)
    assert result.outcome is PrivacyOutcome.BLOCKED_BY_POLICY
    assert result.reason is PrivacyReason.POLICY_DENIED
    assert dispatched == []


@pytest.mark.anyio
async def test_resume_within_the_current_limits_still_dispatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposal = replace(
        _proposal(expires_at=_NOW + timedelta(minutes=5)),
        prepared_bytes=_packet_with_excerpts(16),
    )
    coordinator = _coordinator(
        "approved", expires_at=_NOW + timedelta(minutes=5), proposal=proposal
    )
    dispatched: list[object] = []

    async def dispatch(self: PrivacyCoordinator, *args: object, **kwargs: object) -> object:
        del self, kwargs
        dispatched.append(args)
        return object()

    monkeypatch.setattr(PrivacyCoordinator, "_dispatch_approved", dispatch)

    await coordinator.resume(_REQUEST, _CASE_DIGEST, _deadline())
    assert len(dispatched) == 1


@pytest.mark.anyio
async def test_approved_resume_names_what_the_approved_prepared_packet_carried() -> None:
    """Issue #904: resume dispatches the stored prepared bytes, and records what they carried.

    The resumed success reads the exact approved document, not a rebuilt case, so it names the
    same sent references a first-pass dispatch of those bytes would.
    """

    from yoetz.adapters.providers.fake import scripted_success
    from yoetz.domain.privacy import EgressAuthorization, EgressChannel
    from yoetz.ports.semantic import SemanticJudgment
    from yoetz.protocol.canonical import JsonValue, canonical_encode

    shown = "evd_54000000-0000-4000-8000-000000000011"
    withheld = "evd_54000000-0000-4000-8000-000000000012"
    packet = canonical_encode(
        cast(
            JsonValue,
            {
                "schema": "yoetz.review-packet-case/2",
                "frontier_refs": [shown, withheld],
                "items": [{"item_id": "excerpt-a", "source_ref": shown}],
                "review_packet": {
                    "omissions": [
                        {
                            "subject_ref": withheld,
                            "category": "evidence_excerpt",
                            "reason": "withheld_by_policy",
                        }
                    ]
                },
            },
        )
    )
    proposal = replace(_proposal(expires_at=_NOW + timedelta(minutes=5)), prepared_bytes=packet)
    coordinator = _coordinator(
        "approved", expires_at=_NOW + timedelta(minutes=5), proposal=proposal
    )
    from yoetz.protocol.ids import new_id

    class _FreshIds:
        def new(self, kind: IdKind) -> str:
            return new_id(kind)

    # This dispatch mints an outbound case identity; the matrix's ids never reached one.
    coordinator._ids = cast(IdPort, _FreshIds())  # pyright: ignore[reportPrivateUsage]
    audit = cast(_Audit, coordinator._audit)  # pyright: ignore[reportPrivateUsage]
    gateway = cast(_Gateway, coordinator._gateway)  # pyright: ignore[reportPrivateUsage]
    dispatched: list[bytes] = []
    dispatched_item_ids: list[tuple[str, ...]] = []

    async def authorize(proposal_id: str, case_digest: str, now: datetime) -> EgressAuthorization:
        return EgressAuthorization(
            "aut_54000000-0000-4000-8000-000000000021",
            proposal_id,
            case_digest,
            EgressChannel.LLM_INFERENCE,
            _binding(),
            "semantic-review",
            _scope(),
            proposal.policy_version,
            proposal.policy_digest,
            len(packet),
            proposal.max_tokens,
            ConsentSource.PER_REQUEST_LOCAL_HUMAN,
            now,
            now + timedelta(minutes=1),
            1,
        )

    async def dispatch_external_semantic(
        case: object, authorization: object, deadline: object
    ) -> object:
        del authorization, deadline
        dispatched.append(cast(bytes, getattr(case, "payload")))
        dispatched_item_ids.append(cast(tuple[str, ...], getattr(case, "included_item_ids")))
        return scripted_success(SemanticJudgment("no_material_discrepancy", ())).result

    setattr(audit, "authorize", authorize)
    setattr(gateway, "dispatch_external_semantic", dispatch_external_semantic)

    result = await coordinator.resume(_REQUEST, _CASE_DIGEST, _deadline())

    assert dispatched == [packet]
    assert isinstance(result, SemanticEgressSuccess), result
    assert result.disclosure is not None
    assert result.disclosure.carried == frozenset({shown})
    assert result.disclosure.withheld == frozenset({withheld})
    assert dispatched_item_ids == [("excerpt-a",)]
