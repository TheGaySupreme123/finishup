"""The production human-effects seam must serve per-request disclosure ceremonies."""

# pyright: reportArgumentType=false, reportPrivateUsage=false

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import cast

import pytest

from builders.privacy_policies import minimal_external_policy
from finishup.application.egress import PrivacyCoordinator
from finishup.application.privacy_policy import PrivacyPolicyApplication
from finishup.domain.privacy import (
    ConsentSource,
    DisclosureProposal,
    HumanPrivacyDecision,
    LocalDisclosureSink,
)
from finishup.ports.privacy import EffectivePrivacyPolicy
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.models import DataCategory
from finishup.service.confidential_protocol import (
    ClientOpenEnvelope,
    HumanCeremonyKind,
    PrivacyDecisionResult,
    PrivacyDisclosureDecisionPreview,
    PrivacyPendingTarget,
    ProviderCredentialTarget,
)
from finishup.service.daemon import _LockedHumanEffects, _PrivacyPolicyAppRelay
from finishup.service.human_control import HumanControlError

_NOW = datetime(2026, 8, 5, 12, tzinfo=UTC)
_REQUEST_ID = "req_30000000-0000-4000-8000-000000000001"
_TASK_ID = "tsk_30000000-0000-4000-8000-000000000002"
_PROPOSAL_ID = "ppr_30000000-0000-4000-8000-000000000003"
_CASE_DIGEST = "sha256:" + "c" * 64
_COMMITMENT = "hmac-sha256:" + "d" * 64


class _Clock:
    def now_utc(self) -> datetime:
        return _NOW

    def monotonic_seconds(self) -> float:
        return 1.0


class _PolicyStore:
    def __init__(self) -> None:
        policy = minimal_external_policy()
        self.effective = EffectivePrivacyPolicy(policy, 7, policy.policy_digest)

    async def effective_policy(self, scope: object) -> EffectivePrivacyPolicy:
        assert scope == self.effective.policy.effective_scope
        return self.effective


class _Audit:
    def __init__(self, proposal: DisclosureProposal) -> None:
        self.proposal = proposal
        self.decisions: list[HumanPrivacyDecision] = []

    async def load_disclosure_proposal(self, proposal_id: str) -> DisclosureProposal | None:
        return self.proposal if proposal_id == self.proposal.privacy_proposal_id else None

    async def record_human_decision(self, proposal_id: str, decision: HumanPrivacyDecision) -> None:
        assert proposal_id == self.proposal.privacy_proposal_id
        self.decisions.append(decision)


class _Mac:
    def mac(self, domain: bytes, value: bytes) -> str:
        assert domain == b"yoetz/privacy-audit/local-approval/v1\x00"
        assert value == _CASE_DIGEST.encode("ascii")
        return "hmac-sha256:" + "e" * 64


class _Vault:
    def __setattr__(self, name: str, value: object) -> None:
        object.__setattr__(self, name, value)

    ready: bool = True

    def __init__(self, mode: str = "passphrase") -> None:
        self.mode = SimpleNamespace(value=mode)

    def installation_mac_handle(self, purpose: object) -> _Mac:
        del purpose
        return _Mac()


def _effects(
    *,
    local_sink: LocalDisclosureSink | None = None,
    vault_mode: str = "passphrase",
) -> tuple[_LockedHumanEffects, _Audit]:
    store = _PolicyStore()
    policy = store.effective.policy
    binding = next(
        channel.provider_binding
        for channel in policy.channel_policies
        if channel.provider_binding is not None
    )
    proposal = DisclosureProposal(
        privacy_proposal_id=_PROPOSAL_ID,
        request_id=_REQUEST_ID,
        task_id=_TASK_ID,
        source_item_digests=(),
        prepared_bytes=b'{"claim":"bounded"}',
        approved_categories=(DataCategory.CLAIM_TEXT,),
        blocked_categories=(),
        transformation_summary=(),
        prepared_case_digest=_CASE_DIGEST,
        provider_binding=binding if local_sink is None else None,
        local_sink=local_sink,
        purpose="semantic-review",
        scope=policy.effective_scope,
        policy_version=policy.version,
        policy_digest=policy.policy_digest,
        max_bytes=19,
        max_tokens=5,
        expires_at=_NOW + timedelta(minutes=5),
        proposal_commitment=_COMMITMENT,
    )
    audit = _Audit(proposal)
    app = PrivacyPolicyApplication(
        cast(object, store),
        cast(object, audit),
        cast(object, SimpleNamespace()),
        cast(object, _Clock()),
        cast(object, SimpleNamespace()),
        policy.effective_scope,
    )
    relay = _PrivacyPolicyAppRelay()
    relay.bind(lambda: app)
    return _LockedHumanEffects(
        cast(object, SimpleNamespace()), cast(object, _Vault(vault_mode)), relay
    ), audit


@pytest.mark.anyio
async def test_disclosure_preview_and_approval_use_the_durable_proposal() -> None:
    effects, audit = _effects()
    target = PrivacyPendingTarget("disclosure", _PROPOSAL_ID)

    preview, target_digest, generation = await effects.prepare(
        ClientOpenEnvelope(
            "1" * 64,
            HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION,
            target,
        )
    )

    assert type(preview) is PrivacyDisclosureDecisionPreview
    assert preview.excerpt_preview == '{"claim":"bounded"}'
    assert preview.category == "claim-text"
    assert preview.excerpt_digest == _CASE_DIGEST
    assert generation == 7
    assert target_digest == canonical_digest(
        {"decision_kind": "disclosure", "kind": "privacy_pending", "pending_id": _PROPOSAL_ID}
    )

    result = await effects.decide_privacy(target, "approve", None, 1.0)

    assert result == PrivacyDecisionResult("committed", _CASE_DIGEST)
    assert len(audit.decisions) == 1
    assert audit.decisions[0].approved is True
    assert audit.decisions[0].accepted_diff_digest == _CASE_DIGEST


@pytest.mark.anyio
async def test_expired_disclosure_is_stale_and_cannot_open_a_ceremony() -> None:
    effects, audit = _effects()
    object.__setattr__(audit.proposal, "expires_at", _NOW - timedelta(seconds=1))
    target = PrivacyPendingTarget("disclosure", _PROPOSAL_ID)

    result = await effects.decide_privacy(target, "approve", None, 1.0)

    assert result.status == "stale"
    assert audit.decisions == []
    with pytest.raises(HumanControlError, match="pending_unavailable"):
        await effects.prepare(
            ClientOpenEnvelope(
                "1" * 64,
                HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION,
                target,
            )
        )


@pytest.mark.anyio
async def test_policy_drift_makes_the_disclosure_stale() -> None:
    effects, audit = _effects()
    object.__setattr__(audit.proposal, "policy_digest", "sha256:" + "f" * 64)
    target = PrivacyPendingTarget("disclosure", _PROPOSAL_ID)

    result = await effects.decide_privacy(target, "approve", None, 1.0)

    assert result == PrivacyDecisionResult("stale", _CASE_DIGEST)
    assert audit.decisions == []


@pytest.mark.anyio
async def test_disclosure_denial_records_an_unapproved_decision() -> None:
    effects, audit = _effects()
    target = PrivacyPendingTarget("disclosure", _PROPOSAL_ID)

    result = await effects.decide_privacy(target, "deny", None, 1.0)

    assert result == PrivacyDecisionResult("denied", _CASE_DIGEST)
    assert len(audit.decisions) == 1
    assert audit.decisions[0].approved is False
    assert audit.decisions[0].expires_at is None


@pytest.mark.anyio
async def test_local_sink_disclosure_preview_commits_to_its_destination() -> None:
    effects, _audit = _effects(local_sink=LocalDisclosureSink.AGENT_CONTEXT)
    target = PrivacyPendingTarget("disclosure", _PROPOSAL_ID)

    preview, _target_digest, _generation = await effects.prepare(
        ClientOpenEnvelope(
            "1" * 64,
            HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION,
            target,
        )
    )

    assert type(preview) is PrivacyDisclosureDecisionPreview
    assert preview.destination_commitment == canonical_digest(
        {"local_sink": LocalDisclosureSink.AGENT_CONTEXT.value}
    )


@pytest.mark.anyio
async def test_missing_disclosure_destination_fails_closed() -> None:
    effects, audit = _effects(local_sink=LocalDisclosureSink.AGENT_CONTEXT)
    object.__setattr__(audit.proposal, "local_sink", None)
    target = PrivacyPendingTarget("disclosure", _PROPOSAL_ID)

    with pytest.raises(HumanControlError, match="pending_not_actionable"):
        await effects.prepare(
            ClientOpenEnvelope(
                "1" * 64,
                HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION,
                target,
            )
        )


@pytest.mark.anyio
async def test_disclosure_excerpt_drops_only_a_trailing_partial_utf8_sequence() -> None:
    effects, audit = _effects()
    object.__setattr__(audit.proposal, "prepared_bytes", b"a" * 4_095 + "é".encode())
    target = PrivacyPendingTarget("disclosure", _PROPOSAL_ID)

    preview, _target_digest, _generation = await effects.prepare(
        ClientOpenEnvelope(
            "1" * 64,
            HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION,
            target,
        )
    )

    assert type(preview) is PrivacyDisclosureDecisionPreview
    assert preview.excerpt_preview == "a" * 4_095
    assert "�" not in preview.excerpt_preview
    assert preview.byte_count == 4_097


@pytest.mark.anyio
async def test_keyring_mode_can_preview_and_decide_a_bounded_disclosure() -> None:
    """Keyring is the ordinary production vault mode.

    The passphrase gate made `finishup privacy decide-disclosure` return kind_forbidden on
    every keyring installation, so the confirm_every_request posture had no way to be
    answered at all. Recording an already-bounded disclosure grants no new authority.
    """

    effects, audit = _effects(vault_mode="keyring")
    target = PrivacyPendingTarget("disclosure", _PROPOSAL_ID)

    preview, _target_digest, generation = await effects.prepare(
        ClientOpenEnvelope(
            "1" * 64,
            HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION,
            target,
        )
    )
    assert type(preview) is PrivacyDisclosureDecisionPreview
    assert generation == 7

    result = await effects.decide_privacy(target, "approve", None, 1.0)

    assert result == PrivacyDecisionResult("committed", _CASE_DIGEST)
    assert len(audit.decisions) == 1
    # Resuming an approved proposal must carry per-request local human consent, never a
    # rewrite to baseline policy consent.
    assert audit.decisions[0].consent_source is ConsentSource.PER_REQUEST_LOCAL_HUMAN


@pytest.mark.anyio
async def test_keyring_mode_still_refuses_a_policy_decision() -> None:
    """Policy widening keeps its stronger authority requirement."""

    effects, _audit = _effects(vault_mode="keyring")
    target = PrivacyPendingTarget("policy", _PROPOSAL_ID)

    with pytest.raises(HumanControlError, match="kind_forbidden"):
        await effects.decide_privacy(target, "approve", None, 1.0)


@pytest.mark.anyio
async def test_locked_vault_refuses_a_disclosure_decision() -> None:
    effects, _audit = _effects(vault_mode="keyring")
    cast(_Vault, effects._vault).ready = False
    target = PrivacyPendingTarget("disclosure", _PROPOSAL_ID)

    with pytest.raises(HumanControlError, match="state_forbidden"):
        await effects.decide_privacy(target, "approve", None, 1.0)


@pytest.mark.anyio
async def test_credential_probe_uses_the_ceremonys_trusted_repository_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_effects, _audit = _effects()
    app = cast(PrivacyPolicyApplication, base_effects._privacy_app())
    coordinator = PrivacyCoordinator(
        cast(object, SimpleNamespace()),
        cast(object, SimpleNamespace()),
        cast(object, SimpleNamespace()),
        cast(object, SimpleNamespace()),
        cast(object, _Clock()),
        cast(object, SimpleNamespace()),
    )
    coordinator.bind_policy_application(app)
    relay = _PrivacyPolicyAppRelay()
    relay.bind(lambda: coordinator)
    effects = _LockedHumanEffects(cast(object, SimpleNamespace()), cast(object, _Vault()), relay)
    repository = "hmac-sha256:" + "9" * 64
    target = ProviderCredentialTarget(
        "set",
        "openai",
        "gpt-5",
        "responses",
        "1",
        "credential-probe",
        _CASE_DIGEST,
        canonical_digest({"purpose": "credential-probe"}),
        repository,
    )
    observed: list[object] = []

    async def activate(self: object, scope: object) -> bool:
        del self
        observed.append(scope)
        return True

    async def evaluate(self: object, candidate: object, deadline: object) -> object:
        del self, deadline
        observed.append(candidate)
        return object()

    provider = SimpleNamespace(
        provider_id="openai",
        model="gpt-5",
        endpoint_profile_id="responses",
        endpoint_profile_version="1",
    )

    def load_config(*args: object) -> object:
        del args
        return SimpleNamespace(provider=provider)

    monkeypatch.setattr(PrivacyCoordinator, "activate_repository", activate)
    monkeypatch.setattr(PrivacyCoordinator, "evaluate_semantic", evaluate)
    monkeypatch.setattr("finishup.config.load.load_config", load_config)

    refused = await effects._provider_credential_refused(target, object())

    assert refused is False
    assert len(observed) == 2
    scope = observed[0]
    assert scope.workspace_ref_commitment == repository  # type: ignore[attr-defined]
    candidate = observed[1]
    assert candidate.scope == scope  # type: ignore[attr-defined]
    assert candidate.items[0].source_scope == scope  # type: ignore[attr-defined]
