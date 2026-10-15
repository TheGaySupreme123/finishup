"""Background advice through the composed service, privacy coordinator and provider seam (#1019).

Each case runs the composed scheduler, worker, dispatch and the real ``PrivacyCoordinator`` with
its classifier and audit store; only the provider gateway call and the policy-store reads are
faked. Policy switches go through the same fake store, so the coordinator's own fences (the
preview guard, the profile fence and the repository-authority digest check) see them.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any, cast

import pytest

from builders.privacy_policies import minimal_external_policy
from builders.privacy_widenings import with_llm, with_review
from finishup.adapters.keys.encrypted_vault import EncryptedVaultStore
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.adapters.privacy.gateway import PolicyEnforcingOutboundGateway
from finishup.adapters.providers.fake import scripted_success
from finishup.adapters.providers.openai_responses_factory import provider_binding_from_config
from finishup.application.observation_advice import (
    ADVICE_SEMANTIC_DEFERRED_GAP,
    ADVICE_SEMANTIC_PENDING_GAP,
    ADVICE_SEMANTIC_PREVIEW_REQUIRED_GAP,
    minimized_semantic_evidence_packet,
)
from finishup.application.observation_advice_semantic import (
    ObservationAdviceSemanticAttempt,
    ObservationAdviceSemanticWorker,
    advice_semantic_retry_delay_seconds,
)
from finishup.config.models import FinishUpConfig, VerificationConfig
from finishup.config.write import fireworks_provider
from finishup.domain.observation import AdviceSnapshot
from finishup.domain.privacy import EgressChannel, PrivacyPolicy, ReviewContextProfile
from finishup.ports.control import ServiceState
from finishup.ports.privacy import EffectivePrivacyPolicy
from finishup.ports.secret_memory import SecretPurpose
from finishup.ports.semantic import SemanticJudgment
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.models import StartRequest
from finishup.service.lifecycle import ServiceLifecycle
from finishup.service.ready_composition import build_ready_application_factory
from finishup.service.vault import VaultMode, VaultService
from integration.service.test_ready_composition import (
    _INSTALLATION_ID,  # pyright: ignore[reportPrivateUsage]
    _INSTANCE_ID,  # pyright: ignore[reportPrivateUsage]
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _Diagnostics,  # pyright: ignore[reportPrivateUsage]
    _GenerationStore,  # pyright: ignore[reportPrivateUsage]
    _Paths,  # pyright: ignore[reportPrivateUsage]
)
from unit.application.test_observation_advice_semantic import (
    _COMMITMENT,  # pyright: ignore[reportPrivateUsage]
    _repository,  # pyright: ignore[reportPrivateUsage]
    _Store,  # pyright: ignore[reportPrivateUsage]
)

_UNATTENDED = with_llm(
    with_review(minimal_external_policy(), ReviewContextProfile.ASSISTED),
    provider_binding=provider_binding_from_config(
        fireworks_provider(model="accounts/fireworks/models/minimax-m3")
    ),
)
_PREVIEW = with_llm(_UNATTENDED, preview_required=True)
_STRUCTURAL = with_review(_UNATTENDED, ReviewContextProfile.STRUCTURAL)


def _provider_id(policy: PrivacyPolicy) -> str:
    llm = next(c for c in policy.channel_policies if c.channel is EgressChannel.LLM_INFERENCE)
    assert llm.provider_binding is not None
    return llm.provider_binding.provider_id


@pytest.fixture
def private_advice_root() -> Iterator[Path]:
    # Production path safety rejects Linux's shared /tmp. Use only a root this test owns.
    with TemporaryDirectory(prefix=".yz-n5-advice-test-", dir=Path.home()) as directory:
        root = Path(directory)
        root.chmod(0o700)
        yield root


@dataclass
class _Harness:
    app: Any
    coordinator: Any
    route: Any
    policy: PrivacyPolicy
    sent: list[Any] = field(default_factory=lambda: [])
    generation: int = 0
    provider_raises: bool = False

    def switch(self, policy: PrivacyPolicy) -> None:
        # Every owner policy change is a new repository authority, as in the real store.
        self.policy = policy
        self.generation += 1

    @property
    def now(self) -> str:
        scheduler = self.coordinator.advice_context_builder.semantic_scheduler
        return cast(str, scheduler.now())

    async def build(self, store: _Store) -> AdviceSnapshot:
        snapshot = await self.coordinator.advice_context_builder.build(
            _COMMITMENT, store, yoetz_session_id=self.route.session_id
        )
        assert snapshot is not None
        return cast(AdviceSnapshot, snapshot)

    async def drain(self, store: _Store) -> ObservationAdviceSemanticAttempt:
        worker = ObservationAdviceSemanticWorker(
            repository=store.repository,
            dispatch=self.coordinator.advice_semantic_dispatch,
            service_generation=1,
            lease_owner="svc-test",
            now=lambda: self.now,
            lease_expires_at=lambda: "2099-01-01T00:00:00.000Z",
        )
        drained = await worker.run_once()
        assert drained is not None
        row = store.repository.lookup(
            yoetz_session_id=drained.yoetz_session_id, basis_digest=drained.basis_digest
        )
        assert row is not None
        return row


@asynccontextmanager
async def _composed(
    root: Path, monkeypatch: pytest.MonkeyPatch, policy: PrivacyPolicy
) -> AsyncGenerator[_Harness]:
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "d" * 64,
        instance_id=_INSTANCE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(root / "vault"),
        pristine_state_digest="sha256:" + "e" * 64,
    )
    secret = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(secret, "sha256:" + "f" * 64)
    app = None
    try:
        factory = build_ready_application_factory(
            lifecycle=lifecycle,
            vault=vault,
            config=FinishUpConfig(
                profile="local-openai",
                provider=fireworks_provider(model="accounts/fireworks/models/minimax-m3"),
                verification=VerificationConfig(semantic="required"),
            ),
            paths=_Paths(root),
            clock=clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        context = await factory.context_provider(1, vault.generation)
        app = await factory.open(context)
        assert context.rediscover_pending_verification is not None
        coordinator: Any = getattr(context.rediscover_pending_verification, "__self__")
        started = await app.start(
            StartRequest.model_validate(
                {
                    "protocol_version": "0.1",
                    "schema_version": "1.0.0",
                    "request_id": "req_00000000-0000-4000-8000-000000000003",
                    "mode": "create",
                    "task_title": "Advice regression",
                    "actor": {"actor_id": "pytest", "actor_type": "harness"},
                    "client": {
                        "kind": "test_client",
                        "version": "0.3.0",
                        "integration": "local_cli",
                    },
                    "requested_view": "compact",
                }
            )
        )
        assert started.ok
        created_route = await app.start_catalog.task_route(started.task_id)
        assert created_route is not None
        route = replace(created_route, repository_privacy_commitment=_COMMITMENT)
        harness = _Harness(app, coordinator, route, policy)

        async def resolve_route(_self: object, _session: str) -> object:
            return route

        async def credential_present(*_args: object) -> bool:
            return True

        async def effective_policy(*_args: object) -> EffectivePrivacyPolicy:
            return EffectivePrivacyPolicy(harness.policy, 1, harness.policy.policy_digest)

        async def repository_authority(_self: object, scope: Any) -> object:
            return SimpleNamespace(
                effective=await effective_policy(),
                grant_state="granted",
                repository_privacy_commitment=scope.workspace_ref_commitment,
                authority_digest=canonical_digest({"authority": harness.generation}),
            )

        async def reconcile(*_args: object, **_kwargs: object) -> None:
            return None

        def connected(*_args: object) -> bool:
            return True

        async def fake_provider(
            _self: object, case: Any, authorization: Any, _deadline: object
        ) -> object:
            assert case.authorization_id == authorization.authorization_id
            if harness.provider_raises:
                raise ConnectionError("transport dropped after the request may have left")
            harness.sent.append(case)
            return scripted_success(SemanticJudgment("no_material_discrepancy", ())).result

        assert app.privacy.policy_application is not None
        policy_store = app.privacy.policy_application.policy_store
        monkeypatch.setattr(type(policy_store), "effective_policy", effective_policy)
        monkeypatch.setattr(type(policy_store), "repository_authority", repository_authority)
        monkeypatch.setattr(type(app.start_catalog), "resolve_route", resolve_route)
        monkeypatch.setattr(type(vault), "has_provider_credential", credential_present)
        monkeypatch.setattr(
            PolicyEnforcingOutboundGateway, "has_connected_provider_binding", connected
        )
        monkeypatch.setattr(
            PolicyEnforcingOutboundGateway, "reconcile_repository_policy", reconcile
        )
        monkeypatch.setattr(
            PolicyEnforcingOutboundGateway, "dispatch_external_semantic", fake_provider
        )
        yield harness
        # No disclosure ever waits for the owner. (A refusal at the coordinator's final
        # authority check can leave its prepared proposal ``reserved`` until the short
        # authorization TTL; that pre-existing audit behaviour is shared with explicit checks.)
        catalog_db = getattr(app.start_catalog, "_db")
        assert catalog_db.execute(
            "SELECT COUNT(*) FROM privacy_audit_records WHERE state = 'awaiting_human'"
        ).fetchall() == [(0,)]
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()


def _switch_before(
    monkeypatch: pytest.MonkeyPatch,
    owner: object,
    name: str,
    harness: _Harness,
    policy: PrivacyPolicy,
) -> None:
    """Switch the owner's policy once, immediately before ``owner.name`` runs.

    Patched on the class (slotted instances are read-only); only this instance switches.
    """

    cls = type(owner)
    original = cast(Callable[..., Awaitable[object]], getattr(cls, name))
    switched = False

    async def wrapper(self: object, *args: object, **kwargs: object) -> object:
        nonlocal switched
        if self is owner and not switched:
            switched = True
            harness.switch(policy)
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(cls, name, wrapper)


@pytest.mark.anyio
async def test_background_advice_sends_the_approved_packet(
    private_advice_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with _composed(private_advice_root, monkeypatch, _UNATTENDED) as harness:
        _db, repository = _repository()
        store = _Store(repository)
        snapshot = await harness.build(store)
        gaps = snapshot.confidence_coverage.known_gaps
        assert ADVICE_SEMANTIC_PENDING_GAP in gaps
        assert ADVICE_SEMANTIC_PREVIEW_REQUIRED_GAP not in gaps
        row = await harness.drain(store)
        # The approved packet actually reached the provider seam.
        assert len(harness.sent) == 1
        payload: Any = strict_json_parse(harness.sent[0].payload)
        assert payload["schema"] == "yoetz.review-packet-case/2"
        assert payload["review_context_profile"] == "assisted"
        assert b"failed_command_unresolved" in harness.sent[0].payload
        assert (row.status, row.failure_reason) == ("succeeded", None)
        assert row.provider_identity == _provider_id(_UNATTENDED)
        assert row.attempt_receipt is not None


@pytest.mark.anyio
async def test_preview_policy_skips_background_advice_with_a_typed_reason(
    private_advice_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with _composed(private_advice_root, monkeypatch, _PREVIEW) as harness:
        db, repository = _repository()
        snapshot = await harness.build(_Store(repository))
        gaps = snapshot.confidence_coverage.known_gaps
        assert ADVICE_SEMANTIC_PREVIEW_REQUIRED_GAP in gaps
        assert ADVICE_SEMANTIC_PENDING_GAP not in gaps
        assert snapshot.semantic_attempt_state == "disabled"
        assert db.execute(
            "SELECT COUNT(*) FROM observation_advice_semantic_attempts"
        ).fetchall() == [(0,)]
        assert harness.sent == []


@pytest.mark.anyio
async def test_row_queued_before_a_preview_switch_closes_without_provider_identity(
    private_advice_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with _composed(private_advice_root, monkeypatch, _UNATTENDED) as harness:
        packet = canonical_encode(
            cast(
                JsonValue,
                minimized_semantic_evidence_packet(
                    (), "sha256:" + "b" * 64, coverage_gaps=("source_lag",)
                ),
            )
        )
        harness.switch(_PREVIEW)
        closed = await harness.coordinator.advice_semantic_dispatch(
            ObservationAdviceSemanticAttempt(
                "attempt",
                _COMMITMENT,
                harness.route.session_id,
                "basis",
                canonical_digest(strict_json_parse(packet)),
                ("source_lag",),
                packet,
                "running",
                1,
            )
        )
        assert (closed.status, closed.failure_reason) == ("unavailable", "authorization_missing")
        assert closed.provider_identity is None
        assert harness.sent == []


# (owner attribute path, method): the switch lands just before that method runs.
_SWITCH_POINTS = {
    # After the service's own preflight read, before the coordinator admits the request:
    # refused by the coordinator's preview guard (``policy_denied``).
    "after_preflight": ("privacy", "evaluate_semantic"),
    # After classification, at the coordinator's first authority recheck (``scope_mismatch``).
    "after_classification": ("privacy", "_repository_authority_is_current"),
    # While the disclosure proposal is prepared: refused at the final authority check right
    # before authorize/consume (``scope_mismatch`` from the dispatch step).
    "during_preparation": ("privacy._audit", "prepare_disclosure_proposal"),
}


@pytest.mark.anyio
@pytest.mark.parametrize("point", sorted(_SWITCH_POINTS))
async def test_late_preview_switch_is_recorded_as_unsent(
    private_advice_root: Path, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    """#1019 r3: a refused late switch is not a provider failure and charges no provider rate."""

    async with _composed(private_advice_root, monkeypatch, _UNATTENDED) as harness:
        path, name = _SWITCH_POINTS[point]
        owner: object = harness.app
        for part in path.split("."):
            owner = getattr(owner, part)
        _db, repository = _repository()
        store = _Store(repository)
        assert (
            ADVICE_SEMANTIC_PENDING_GAP
            in (await harness.build(store)).confidence_coverage.known_gaps
        )
        _switch_before(monkeypatch, owner, name, harness, _PREVIEW)
        row = await harness.drain(store)
        assert harness.generation == 1, "the switch point was not reached"
        assert harness.sent == []
        assert (row.status, row.failure_reason) == ("unavailable", "authorization_missing")
        assert row.provider_identity is None
        assert row.attempt_receipt is not None
        # Base-only retry for the same condition, never the provider-failure growth.
        assert advice_semantic_retry_delay_seconds(row, generation=2, base_seconds=180) == 180
        # No session provider-rate charge: a different condition is admitted at once.
        harness.switch(_UNATTENDED)
        store.gaps = ("source_lag",)
        snapshot = await harness.build(store)
        gaps = snapshot.confidence_coverage.known_gaps
        assert ADVICE_SEMANTIC_DEFERRED_GAP not in gaps
        assert ADVICE_SEMANTIC_PENDING_GAP in gaps


@pytest.mark.anyio
async def test_outcome_unknown_keeps_provider_identity_and_charges_the_rate(
    private_advice_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with _composed(private_advice_root, monkeypatch, _UNATTENDED) as harness:
        _db, repository = _repository()
        store = _Store(repository)
        await harness.build(store)
        harness.provider_raises = True
        row = await harness.drain(store)
        # The request may have left the machine: provenance stays truthful.
        assert (row.status, row.failure_reason) == ("failed", "provider_failed")
        assert row.provider_identity == _provider_id(_UNATTENDED)
        store.gaps = ("source_lag",)
        snapshot = await harness.build(store)
        assert ADVICE_SEMANTIC_DEFERRED_GAP in snapshot.confidence_coverage.known_gaps


@pytest.mark.anyio
async def test_profile_tightened_while_waiting_for_admission_never_sends_the_stale_selection(
    private_advice_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with _composed(private_advice_root, monkeypatch, _UNATTENDED) as harness:
        _db, repository = _repository()
        store = _Store(repository)
        await harness.build(store)
        # The service composed an Assisted candidate; Structural is in force at admission.
        _switch_before(monkeypatch, harness.app.privacy, "evaluate_semantic", harness, _STRUCTURAL)
        row = await harness.drain(store)
        assert harness.sent == []
        assert (row.status, row.failure_reason) == ("unavailable", "authorization_missing")
        assert row.provider_identity is None
        # The next admission is rebuilt from the effective profile.
        store.gaps = ("source_lag",)
        await harness.build(store)
        rebuilt = await harness.drain(store)
        assert rebuilt.status == "succeeded"
        (case,) = harness.sent
        payload: Any = strict_json_parse(case.payload)
        assert payload["review_context_profile"] == "structural"
        assert all(row["category"] != "finding_summary" for row in payload["items"])
