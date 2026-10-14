"""Automatic advice must retain approved content through the semantic assembler (#1019)."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any, cast

import pytest

from integration.service.test_ready_composition import (
    _INSTALLATION_ID,  # pyright: ignore[reportPrivateUsage]
    _INSTANCE_ID,  # pyright: ignore[reportPrivateUsage]
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _Diagnostics,  # pyright: ignore[reportPrivateUsage]
    _GenerationStore,  # pyright: ignore[reportPrivateUsage]
    _Paths,  # pyright: ignore[reportPrivateUsage]
    _runtime_route,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.adapters.keys.encrypted_vault import EncryptedVaultStore
from yoetz.adapters.keys.secret_memory import LocalSecretMemory
from yoetz.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from yoetz.application.observation_advice import minimized_semantic_evidence_packet
from yoetz.application.observation_advice_semantic import ObservationAdviceSemanticAttempt
from yoetz.config.models import VerificationConfig, YoetzConfig
from yoetz.config.write import fireworks_provider
from yoetz.domain.privacy import PrivacyDecision, PrivacyOutcome
from yoetz.ports.control import ServiceState
from yoetz.ports.secret_memory import SecretPurpose
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from yoetz.protocol.models import DataCategory
from yoetz.service.lifecycle import ServiceLifecycle
from yoetz.service.ready_composition import build_ready_application_factory
from yoetz.service.vault import VaultMode, VaultService


@pytest.fixture
def private_advice_root() -> Iterator[Path]:
    # Production path safety rejects Linux's shared /tmp. Use only a root this test owns.
    with TemporaryDirectory(prefix=".yz-n5-advice-test-", dir=Path.home()) as directory:
        root = Path(directory)
        root.chmod(0o700)
        yield root


@pytest.mark.anyio
async def test_service_advice_retains_approved_packet(
    private_advice_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path = private_advice_root
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
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "e" * 64,
    )
    secret = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(secret, "sha256:" + "f" * 64)
    app = None
    try:
        factory = build_ready_application_factory(
            lifecycle=lifecycle,
            vault=vault,
            config=YoetzConfig(
                profile="local-openai",
                provider=fireworks_provider(model="accounts/fireworks/models/minimax-m3"),
                verification=VerificationConfig(semantic="required"),
            ),
            paths=_Paths(tmp_path),
            clock=clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        context = await factory.context_provider(1, vault.generation)
        app = await factory.open(context)
        assert context.rediscover_pending_verification is not None
        coordinator: Any = getattr(context.rediscover_pending_verification, "__self__")
        route = replace(_runtime_route(), repository_privacy_commitment="hmac-sha256:" + "a" * 64)

        async def resolve_route(_self: object, _session: str) -> object:
            return route

        async def credential_present(*_args: object) -> bool:
            return True

        async def activate(*_args: object) -> bool:
            return True

        evaluated: list[object] = []

        async def evaluate(_self: object, candidate: Any, _deadline: object) -> object:
            evaluated.append(candidate)
            # Run the real privacy assembler on the exact candidate the service produced.
            from builders.privacy_policies import minimal_external_policy
            from yoetz.ports.privacy import EffectivePrivacyPolicy

            policy = minimal_external_policy()
            enforcer = LocalPrivacyEnforcer()
            classified = enforcer.classify(
                candidate, EffectivePrivacyPolicy(policy, 1, policy.policy_digest)
            )
            minimized = enforcer.minimize_and_scan(
                classified,
                PrivacyDecision(
                    tuple(item.item_id for item in candidate.items),
                    (),
                    PrivacyOutcome.COMPLETED,
                    None,
                ),
            )
            assert minimized.included_item_ids, "approved advice was discarded by assembly"
            payload: Any = strict_json_parse(minimized.prepared_bytes)
            assert payload["schema"] == "yoetz.review-packet-case/2"
            assert any("source_lag" in row["content"] for row in payload["items"])
            assert {row["category"] for row in payload["items"]} <= {
                DataCategory.BOUNDED_STRUCTURAL_METADATA.value,
                DataCategory.FINDING_SUMMARY.value,
            }
            return SimpleNamespace()  # Only the producer/assembler boundary is under test here.

        from builders.privacy_policies import minimal_external_policy
        from builders.privacy_widenings import with_llm
        from yoetz.adapters.providers.openai_responses_factory import provider_binding_from_config
        from yoetz.ports.privacy import EffectivePrivacyPolicy

        policy = with_llm(
            minimal_external_policy(),
            provider_binding=provider_binding_from_config(
                fireworks_provider(model="accounts/fireworks/models/minimax-m3")
            ),
        )

        async def effective_policy(*_args: object) -> EffectivePrivacyPolicy:
            return EffectivePrivacyPolicy(policy, 1, policy.policy_digest)

        assert app.privacy.policy_application is not None
        monkeypatch.setattr(
            type(app.privacy.policy_application.policy_store), "effective_policy", effective_policy
        )
        monkeypatch.setattr(type(app.start_catalog), "resolve_route", resolve_route)
        monkeypatch.setattr(type(vault), "has_provider_credential", credential_present)
        from yoetz.adapters.privacy.gateway import PolicyEnforcingOutboundGateway

        def connected(*_args: object) -> bool:
            return True

        monkeypatch.setattr(
            PolicyEnforcingOutboundGateway, "has_connected_provider_binding", connected
        )
        monkeypatch.setattr(type(app.privacy), "activate_repository", activate)
        monkeypatch.setattr(type(app.privacy), "evaluate_semantic", evaluate)
        packet = canonical_encode(
            cast(
                JsonValue,
                minimized_semantic_evidence_packet(
                    (),
                    "sha256:" + "b" * 64,
                    coverage_gaps=("source_lag",),
                    finding_summaries=("rule",),
                ),
            )
        )
        attempt = ObservationAdviceSemanticAttempt(
            "attempt",
            "hmac-sha256:" + "a" * 64,
            route.session_id,
            "basis",
            canonical_digest(strict_json_parse(packet)),
            ("source_lag",),
            packet,
            "running",
            1,
        )
        await coordinator.advice_semantic_dispatch(attempt)
        assert len(evaluated) == 1
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()
