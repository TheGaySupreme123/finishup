"""A machine-only privacy policy proposal opens its ceremony and decides (issue #1322).

Outside any repository, ``privacy propose`` makes a single-layer transition of the installation
ceiling. The SQLite policy store persists it with one synthetic machine ``replace`` member, so the
production human-effects seam reads that member back. The ceremony must still show the whole
``before -> after`` widening, and the decision must commit or deny the exact proposal. The real
catalog store runs here because the in-memory store never surfaces the synthetic member.
"""

# pyright: reportArgumentType=false, reportPrivateUsage=false

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import apsw
import pytest

from builders.privacy_policies import (
    SUCCESSOR_POLICY_DIGEST,
    local_only_policy,
    machine_scope,
)
from finishup.adapters.privacy.catalog import CatalogPrivacyPolicyStore
from finishup.application.privacy_policy import (
    PolicyDecisionRequired,
    PrivacyPolicyApplication,
    ProposePrivacyPolicyRequest,
    privacy_policy_changes,
    privacy_propose_policy,
)
from finishup.domain.privacy import AuthorizationScopeKind, PrivacyPolicy
from finishup.ports.privacy import (
    EffectivePrivacyPolicy,
    HumanAuthorityCapability,
    ProviderReconciliation,
)
from finishup.ports.secret_memory import HumanAuthorizationProof
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.ids import IdKind
from finishup.protocol.models import DataCategory
from finishup.service.confidential_protocol import (
    ClientOpenEnvelope,
    HumanCeremonyKind,
    PrivacyDecisionResult,
    PrivacyPendingTarget,
    PrivacyPolicyDecisionPreview,
    _preview_from_json,
    _preview_to_json,
)
from finishup.service.daemon import _LockedHumanEffects, _PrivacyPolicyAppRelay

pytestmark = pytest.mark.anyio

_NOW = datetime(2026, 11, 7, 12, tzinfo=UTC)
_PROPOSAL_ID = "ppr_40000000-0000-4000-8000-000000000001"
_SERVICE_GENERATION = 3
_VAULT_GENERATION = 5
_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class _Clock:
    def now_utc(self) -> datetime:
        return _NOW

    def monotonic_seconds(self) -> float:
        return 1.0


class _Ids:
    def new(self, kind: IdKind) -> str:
        assert kind is IdKind.PRIVACY_PROPOSAL
        return _PROPOSAL_ID


class _Gateway:
    def __init__(self) -> None:
        self.reconciled: list[EffectivePrivacyPolicy] = []

    @asynccontextmanager
    async def authority_mutation_fence(self) -> AsyncGenerator[None]:
        yield

    async def reconcile_policy(
        self, policy: EffectivePrivacyPolicy, human_authority: HumanAuthorityCapability
    ) -> ProviderReconciliation:
        del human_authority
        self.reconciled.append(policy)
        return ProviderReconciliation(policy.generation, 0, 0, ())


class _Mac:
    def mac(self, domain: bytes, value: bytes) -> str:
        assert domain == b"yoetz/privacy-audit/local-approval/v1\x00"
        del value
        return "hmac-sha256:" + "e" * 64


class _Vault:
    ready = True
    generation = _VAULT_GENERATION
    mode = SimpleNamespace(value="passphrase")

    def installation_mac_handle(self, purpose: object) -> _Mac:
        del purpose
        return _Mac()


def _database() -> apsw.Connection:
    db = apsw.Connection(":memory:")
    for migration in sorted((_REPOSITORY_ROOT / "migrations/catalog").glob("*.sql")):
        db.execute(migration.read_text(encoding="utf-8"))
    return db


def _widen_agent_context(policy: PrivacyPolicy) -> PrivacyPolicy:
    categories = (*policy.agent_context_categories, DataCategory.CLAIM_TEXT)
    return replace(
        policy,
        agent_context_categories=tuple(sorted(set(categories), key=lambda item: item.value)),
    )


def _admit_input_root(policy: PrivacyPolicy) -> PrivacyPolicy:
    return replace(policy, admitted_input_roots=("/data",))


type _Widening = Callable[[PrivacyPolicy], PrivacyPolicy]


@pytest.fixture(params=[_widen_agent_context, _admit_input_root], ids=["agent_context", "root"])
def widening(request: pytest.FixtureRequest) -> _Widening:
    return cast(_Widening, request.param)


async def _propose_machine_widening(
    widen: _Widening,
) -> tuple[_LockedHumanEffects, CatalogPrivacyPolicyStore, _Gateway, PolicyDecisionRequired]:
    store = CatalogPrivacyPolicyStore(_database(), _Clock())
    seed = local_only_policy()
    await store.seed_if_absent(seed)
    current = await store.effective_policy(machine_scope())
    candidate = replace(
        widen(seed),
        version=seed.version + 1,
        policy_digest=SUCCESSOR_POLICY_DIGEST,
        supersedes_policy_digest=seed.policy_digest,
    )
    gateway = _Gateway()
    app = PrivacyPolicyApplication(
        store,
        cast(object, SimpleNamespace()),
        gateway,
        _Clock(),
        _Ids(),
        machine_scope(),
    )
    proposed = await privacy_propose_policy(
        app, ProposePrivacyPolicyRequest(current.effective_digest, candidate)
    )
    assert type(proposed) is PolicyDecisionRequired
    relay = _PrivacyPolicyAppRelay()
    relay.bind(lambda: app)
    lifecycle = SimpleNamespace(instance=SimpleNamespace(generation=_SERVICE_GENERATION))
    effects = _LockedHumanEffects(cast(object, lifecycle), cast(object, _Vault()), relay)
    return effects, store, gateway, proposed


async def test_a_machine_only_proposal_previews_the_whole_ceiling_diff(widening: _Widening) -> None:
    effects, store, _gateway, proposed = await _propose_machine_widening(widening)
    stored = await store.load_transition(_PROPOSAL_ID)
    # The precondition this regression covers: the store hands back the synthetic machine member.
    assert [(m.scope.kind, m.action) for m in stored.proposal.members] == [
        (AuthorizationScopeKind.MACHINE, "replace")
    ]
    target = PrivacyPendingTarget("policy", _PROPOSAL_ID)

    preview, target_digest, generation = await effects.prepare(
        ClientOpenEnvelope("1" * 64, HumanCeremonyKind.PRIVACY_POLICY_DECISION, target)
    )

    # A single-layer transition carries the complete diff in ``changes``, exactly as before the
    # store began persisting members, so every released client can verify and render it.
    assert type(preview) is PrivacyPolicyDecisionPreview
    assert preview.pending_id == _PROPOSAL_ID
    assert preview.members == ()
    assert preview.changes == privacy_policy_changes(
        local_only_policy(), proposed.prepared.proposal.proposed_policy
    )
    assert any(change.widens for change in preview.changes)
    assert preview.diff_digest == proposed.prepared.exact_diff_digest
    assert _preview_from_json(_preview_to_json(preview)) == preview
    assert target_digest == canonical_digest(
        {"decision_kind": "policy", "kind": "privacy_pending", "pending_id": _PROPOSAL_ID}
    )
    assert generation == proposed.prepared.proposal.expected_generation


async def test_a_machine_only_proposal_commits_on_approval(widening: _Widening) -> None:
    effects, store, gateway, proposed = await _propose_machine_widening(widening)
    target = PrivacyPendingTarget("policy", _PROPOSAL_ID)
    before = await store.effective_policy(machine_scope())
    _preview, target_digest, generation = await effects.prepare(
        ClientOpenEnvelope("1" * 64, HumanCeremonyKind.PRIVACY_POLICY_DECISION, target)
    )
    proof = HumanAuthorizationProof(
        "proof-1",
        "privacy_policy_widen",
        target_digest,
        _SERVICE_GENERATION,
        _VAULT_GENERATION,
        generation,
        1.0,
        60.0,
    )

    result = await effects.decide_privacy(target, "approve", proof, 2.0)

    assert result == PrivacyDecisionResult("committed", proposed.prepared.prepared_digest)
    after = await store.effective_policy(machine_scope())
    assert after.policy == proposed.prepared.proposal.proposed_policy
    assert after.generation > before.generation
    assert [item.policy for item in gateway.reconciled] == [after.policy]
    # The decided proposal cannot open a second ceremony as if it were still pending.
    with pytest.raises(ValueError, match="privacy_policy_transition_unavailable"):
        await store.load_pending_transition(_PROPOSAL_ID)


async def test_a_machine_only_proposal_leaves_the_policy_on_denial(widening: _Widening) -> None:
    effects, store, gateway, proposed = await _propose_machine_widening(widening)
    target = PrivacyPendingTarget("policy", _PROPOSAL_ID)
    before = await store.effective_policy(machine_scope())
    await effects.prepare(
        ClientOpenEnvelope("1" * 64, HumanCeremonyKind.PRIVACY_POLICY_DECISION, target)
    )

    result = await effects.decide_privacy(target, "deny", None, 2.0)

    assert result == PrivacyDecisionResult("denied", proposed.prepared.prepared_digest)
    after = await store.effective_policy(machine_scope())
    assert after == before
    assert [item.policy for item in gateway.reconciled] == [before.policy]
