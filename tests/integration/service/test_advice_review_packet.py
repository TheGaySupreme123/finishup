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
)
from unit.application.test_observation_advice_semantic import (
    _COMMITMENT,  # pyright: ignore[reportPrivateUsage]
    _repository,  # pyright: ignore[reportPrivateUsage]
    _Store,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.adapters.keys.encrypted_vault import EncryptedVaultStore
from yoetz.adapters.keys.secret_memory import LocalSecretMemory
from yoetz.adapters.providers.fake import scripted_success
from yoetz.application.observation_advice import (
    ADVICE_SEMANTIC_PENDING_GAP,
    ADVICE_SEMANTIC_PREVIEW_REQUIRED_GAP,
    minimized_semantic_evidence_packet,
)
from yoetz.application.observation_advice_semantic import (
    ObservationAdviceSemanticAttempt,
    ObservationAdviceSemanticWorker,
)
from yoetz.config.models import VerificationConfig, YoetzConfig
from yoetz.config.write import fireworks_provider
from yoetz.domain.privacy import EgressChannel, PrivacyPolicy
from yoetz.ports.control import ServiceState
from yoetz.ports.secret_memory import SecretPurpose
from yoetz.ports.semantic import SemanticJudgment
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from yoetz.protocol.models import StartRequest
from yoetz.service.lifecycle import ServiceLifecycle
from yoetz.service.ready_composition import build_ready_application_factory
from yoetz.service.vault import VaultMode, VaultService


def unattended_provider_id(policy: PrivacyPolicy) -> str:
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


@pytest.mark.anyio
@pytest.mark.parametrize("preview", [False, True])
async def test_background_advice_sends_approved_packet_or_skips_for_preview(
    private_advice_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    preview: bool,
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

        async def resolve_route(_self: object, _session: str) -> object:
            return route

        async def credential_present(*_args: object) -> bool:
            return True

        sent: list[Any] = []

        async def fake_provider(
            _self: object, case: Any, authorization: Any, _deadline: object
        ) -> object:
            assert case.authorization_id == authorization.authorization_id
            sent.append(case)
            return scripted_success(SemanticJudgment("no_material_discrepancy", ())).result

        from builders.privacy_policies import minimal_external_policy
        from builders.privacy_widenings import with_llm
        from yoetz.adapters.providers.openai_responses_factory import provider_binding_from_config
        from yoetz.ports.privacy import EffectivePrivacyPolicy

        unattended = with_llm(
            minimal_external_policy(),
            provider_binding=provider_binding_from_config(
                fireworks_provider(model="accounts/fireworks/models/minimax-m3")
            ),
        )
        preview_policy = with_llm(unattended, preview_required=True)
        current = {"policy": preview_policy if preview else unattended}

        async def effective_policy(*_args: object) -> EffectivePrivacyPolicy:
            policy = current["policy"]
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

        async def repository_authority(_self: object, scope: Any) -> object:
            return SimpleNamespace(
                effective=await effective_policy(),
                grant_state="granted",
                repository_privacy_commitment=scope.workspace_ref_commitment,
                authority_digest="sha256:" + "9" * 64,
            )

        async def reconcile(*_args: object, **_kwargs: object) -> None:
            return None

        monkeypatch.setattr(
            type(app.privacy.policy_application.policy_store),
            "repository_authority",
            repository_authority,
        )
        monkeypatch.setattr(
            PolicyEnforcingOutboundGateway, "reconcile_repository_policy", reconcile
        )
        monkeypatch.setattr(
            PolicyEnforcingOutboundGateway, "dispatch_external_semantic", fake_provider
        )
        # The background path: the composed scheduler admits (or skips) the advice the hook
        # build asks for, and the worker drains the row through the composed dispatch.
        db, repository = _repository()
        store = _Store(repository)
        builder = coordinator.advice_context_builder
        snapshot = await builder.build(_COMMITMENT, store, yoetz_session_id=route.session_id)
        assert snapshot is not None
        gaps = snapshot.confidence_coverage.known_gaps
        rows = db.execute(
            "SELECT status, failure_reason, provider_identity "
            "FROM observation_advice_semantic_attempts"
        ).fetchall()
        if preview:
            # Skipped with a typed reason: no row, provider identity, backoff or proposal.
            assert ADVICE_SEMANTIC_PREVIEW_REQUIRED_GAP in gaps
            assert ADVICE_SEMANTIC_PENDING_GAP not in gaps
            assert snapshot.semantic_attempt_state == "disabled"
            assert rows == []
            assert sent == []
        else:
            assert ADVICE_SEMANTIC_PENDING_GAP in gaps
            assert ADVICE_SEMANTIC_PREVIEW_REQUIRED_GAP not in gaps
            assert [row[0] for row in rows] == ["pending"]
            worker = ObservationAdviceSemanticWorker(
                repository=repository,
                dispatch=coordinator.advice_semantic_dispatch,
                service_generation=1,
                lease_owner="svc-test",
                now=lambda: "2026-09-08T21:00:00.000Z",
                lease_expires_at=lambda: "2026-09-08T23:00:00.000Z",
            )
            drained = await worker.run_once()
            assert drained is not None
            # The approved packet actually reached the provider seam.
            assert len(sent) == 1
            payload: Any = strict_json_parse(sent[0].payload)
            assert payload["schema"] == "yoetz.review-packet-case/2"
            assert payload["review_context_profile"] == unattended.review_context_profile.value
            assert b"failed_command_unresolved" in sent[0].payload
            ((status, failure, provider),) = db.execute(
                "SELECT status, failure_reason, provider_identity "
                "FROM observation_advice_semantic_attempts"
            ).fetchall()
            assert (status, failure) == ("succeeded", None)
            assert provider == unattended_provider_id(unattended)

            # A row queued before the owner switched to a preview-required policy closes
            # without a provider attempt, provider identity or awaiting-human proposal.
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
            current["policy"] = preview_policy
            queued = ObservationAdviceSemanticAttempt(
                "attempt",
                _COMMITMENT,
                route.session_id,
                "basis",
                canonical_digest(strict_json_parse(packet)),
                ("source_lag",),
                packet,
                "running",
                1,
            )
            closed = await coordinator.advice_semantic_dispatch(queued)
            assert (closed.status, closed.failure_reason) == (
                "unavailable",
                "authorization_missing",
            )
            assert closed.provider_identity is None
            assert closed.attempt_receipt is None
            assert len(sent) == 1
        catalog_db = getattr(app.start_catalog, "_db")
        assert (
            catalog_db.execute(
                "SELECT COUNT(*) FROM privacy_audit_records "
                "WHERE state IN ('awaiting_human', 'reserved')"
            ).fetchone()[0]
            == 0
        )
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()
