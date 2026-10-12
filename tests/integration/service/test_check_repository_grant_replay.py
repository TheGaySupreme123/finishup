"""Same-request replay of a check suspended on a standing repository grant (issue #427).

The full ready composition (SQLite ledger, encrypted object store, catalog privacy store) runs a
``semantic_required`` check that suspends with the ``repository_privacy_setup`` continuation, the
trusted ceremony grants the Assisted-review policy for the repository, and the exact original
request is replayed. The replay must consume the new authority and reach a terminal result; it
must never wedge the frozen case behind a non-retryable STORAGE_CORRUPT.

The ledger deliberately holds an ``evidence_recorded/1.1.0`` event carrying a ``digest_binding``:
the resume checkpoint's projection snapshot records no schema version, and the decoder used to pin
every family to "1.0.0", so this evidence made every deferred rehydration of the frozen case fail
as corruption. The restart variants exercise the same decode through ledger recovery, which is the
path a service re-ready between the ceremony and the replay takes.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

import yoetz.adapters.sqlite.connection as connection_module
from builders.privacy_policies import minimal_external_policy
from yoetz.adapters.keys.encrypted_vault import EncryptedVaultStore
from yoetz.adapters.keys.secret_memory import LocalSecretMemory
from yoetz.application.privacy_policy import (
    DecidePrivacyPolicyRequest,
    PolicyDecisionRequired,
    ProposePrivacyPolicyRequest,
    decide_privacy_policy,
    privacy_propose_policy,
)
from yoetz.application.service import Application
from yoetz.config.models import YoetzConfig
from yoetz.config.write import fireworks_provider
from yoetz.domain.privacy import AuthorizationScope, AuthorizationScopeKind
from yoetz.ports.control import RepositoryPrivacyContext, ServiceState
from yoetz.ports.diagnostics import StartupCheckResult
from yoetz.ports.ledger import CheckAwaitingHuman, CheckCommitResult
from yoetz.ports.privacy import HumanAuthorityCapability, HumanPolicyDecision
from yoetz.ports.secret_memory import HumanAuthorizationProof, SecretPurpose
from yoetz.protocol.canonical import JsonValue, canonical_digest
from yoetz.protocol.models import CheckRequest, PublishWorkRequest, StartRequest, StatusRequest
from yoetz.service.lifecycle import ServiceLifecycle
from yoetz.service.ready_composition import build_ready_application_factory
from yoetz.service.vault import VaultMode, VaultService, provider_credential_profile_binding

_INSTALLATION_ID = "ins_00000000-0000-4000-8000-000000000001"
_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000002"
_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "4" * 64, "git_common_root")
_CHECK_REQUEST_ID = "req_00000000-0000-4000-8000-000000000427"
_COMMON: dict[str, JsonValue] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
    "client": {"kind": "cooperative_agent", "version": "0.1.0", "integration": "cooperative_mcp"},
}


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 8, 27, 17, 5, 0, tzinfo=UTC)

    def now_utc(self) -> datetime:
        return self.now

    def monotonic_seconds(self) -> float:
        return 1.0


class _GenerationStore:
    def advance(self, instance_id: str) -> int:
        assert instance_id == _INSTANCE_ID
        return 1


class _Paths:
    def __init__(self, bundle: Path) -> None:
        self._bundle = bundle

    @property
    def bundle(self) -> Path:
        return self._bundle

    @property
    def state(self) -> Path:
        return self._bundle / "state"


class _Diagnostics:
    def record(self, result: StartupCheckResult) -> None:
        assert type(result) is StartupCheckResult


def _accept_private_path(_path: Path) -> None:
    return None


@pytest.fixture(autouse=True)
def _private_paths(monkeypatch: pytest.MonkeyPatch) -> None:  # pyright: ignore[reportUnusedFunction]
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _accept_private_path)


def _event_batches() -> tuple[tuple[str, list[JsonValue]], ...]:
    """A plan, an action, digest-bound evidence (1.1.0), a result, and a completion claim."""

    return (
        (
            "req_00000000-0000-4000-8000-000000000102",
            [
                {
                    "event_id": "evt_00000000-0000-4000-8000-000000000201",
                    "schema": {"name": "plan_published", "version": "1.0.0"},
                    "occurred_at": "2026-08-27T17:00:00.000Z",
                    "causal_parents": [],
                    "payload": {
                        "plan_version": 1,
                        "summary": "Replay a suspended check after the repository grant.",
                        "obligation_refs": [],
                    },
                    "artifact_refs": [],
                    "evidence_refs": [],
                }
            ],
        ),
        (
            "req_00000000-0000-4000-8000-000000000103",
            [
                {
                    "event_id": "evt_00000000-0000-4000-8000-000000000202",
                    "schema": {"name": "action_recorded", "version": "1.0.0"},
                    "occurred_at": "2026-08-27T17:01:00.000Z",
                    "causal_parents": ["evt_00000000-0000-4000-8000-000000000201"],
                    "payload": {
                        "action_id": "act_00000000-0000-4000-8000-000000000201",
                        "action_kind": "review",
                        "description": "Reviewed the change under test.",
                    },
                    "artifact_refs": [],
                    "evidence_refs": [],
                },
                {
                    "event_id": "evt_00000000-0000-4000-8000-000000000203",
                    "schema": {"name": "evidence_recorded", "version": "1.1.0"},
                    "occurred_at": "2026-08-27T17:02:00.000Z",
                    "causal_parents": ["evt_00000000-0000-4000-8000-000000000202"],
                    "payload": {
                        "evidence_id": "evd_00000000-0000-4000-8000-000000000201",
                        "evidence_kind": "artifact",
                        "strength": "content_digest",
                        "content_digest": "sha256:" + "11" * 32,
                        "observed_at": "2026-08-27T17:02:00.000Z",
                        "description": "Diff of the reviewed change.",
                        "digest_binding": {
                            "subject": "source_diff",
                            "content_availability": "digest_only",
                            "byte_count": 128,
                            "provenance": "caller_asserted",
                        },
                    },
                    "artifact_refs": [],
                    "evidence_refs": [],
                },
                {
                    "event_id": "evt_00000000-0000-4000-8000-000000000204",
                    "schema": {"name": "result_recorded", "version": "1.0.0"},
                    "occurred_at": "2026-08-27T17:03:00.000Z",
                    "causal_parents": ["evt_00000000-0000-4000-8000-000000000202"],
                    "payload": {
                        "result_id": "res_00000000-0000-4000-8000-000000000201",
                        "action_id": "act_00000000-0000-4000-8000-000000000201",
                        "outcome": "success",
                        "summary": "The review completed.",
                    },
                    "artifact_refs": [],
                    "evidence_refs": [],
                },
                {
                    "event_id": "evt_00000000-0000-4000-8000-000000000205",
                    "schema": {"name": "claim_recorded", "version": "1.0.0"},
                    "occurred_at": "2026-08-27T17:04:00.000Z",
                    "causal_parents": ["evt_00000000-0000-4000-8000-000000000204"],
                    "payload": {
                        "claim_id": "clm_00000000-0000-4000-8000-000000000201",
                        "claim_kind": "completion",
                        "statement": "The change was reviewed against its diff.",
                        "supporting_refs": ["evd_00000000-0000-4000-8000-000000000201"],
                    },
                    "artifact_refs": [],
                    "evidence_refs": [],
                },
            ],
        ),
    )


async def _grant_repository_policy(app: Application, vault: VaultService, clock: _Clock) -> None:
    """Run the trusted ceremony: propose the widened workspace policy, then approve it."""

    policy_app = app.privacy.policy_application
    assert policy_app is not None
    scope = AuthorizationScope(
        AuthorizationScopeKind.WORKSPACE, _INSTALLATION_ID, _REPOSITORY.commitment
    )
    authority = await policy_app.policy_store.repository_authority(scope)
    assert authority.grant_state == "missing"
    candidate = replace(
        minimal_external_policy(), effective_scope=scope, created_at=clock.now_utc()
    )
    proposed = await privacy_propose_policy(
        policy_app,
        ProposePrivacyPolicyRequest(
            authority.effective.effective_digest, candidate, authority.authority_digest, scope
        ),
    )
    assert type(proposed) is PolicyDecisionRequired
    await decide_privacy_policy(
        policy_app,
        DecidePrivacyPolicyRequest(
            proposed.prepared,
            HumanPolicyDecision(
                proposed.prepared.prepared_digest, True, clock.now_utc(), "hmac-sha256:" + "5" * 64
            ),
            HumanAuthorityCapability(
                "established_passphrase",
                canonical_digest({"source": "test"}),
                1,
                str(getattr(vault.mode, "value", vault.mode)),
                vault.generation,
                True,
            ),
        ),
    )
    granted = await policy_app.policy_store.repository_authority(scope)
    assert granted.grant_state == "granted"


async def _store_provider_credential(
    vault: VaultService, memory: LocalSecretMemory, provider: object
) -> None:
    binding = provider_credential_profile_binding(
        provider.provider_id,  # type: ignore[attr-defined]
        provider.model,  # type: ignore[attr-defined]
        provider.endpoint_profile_id,  # type: ignore[attr-defined]
        provider.endpoint_profile_version,  # type: ignore[attr-defined]
    )
    proof = HumanAuthorizationProof(
        "provider-proof-after-composition",
        "provider_credential_set",
        binding.target_digest("set"),
        1,
        vault.generation,
        None,
        1.0,
        60.0,
    )
    credential = memory.capture(
        SecretPurpose.PROVIDER_CREDENTIAL, bytearray(b"test-provider-token")
    )
    await vault.store_provider_credential("set", binding, credential, proof, 2.0)


@pytest.mark.parametrize(
    "variant",
    ["same_service", "same_service_with_credential", "restart", "restart_with_credential"],
)
@pytest.mark.anyio
async def test_same_request_replay_after_repository_grant_reaches_terminal_result(
    tmp_path: Path, variant: str
) -> None:
    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        singleton_lock_path=tmp_path / "lifecycle.lock",
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
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "f" * 64)
    provider = fireworks_provider(model="accounts/fireworks/models/minimax-m3")
    config = YoetzConfig(profile="local-openai", provider=provider)
    app = None
    try:
        factory = build_ready_application_factory(
            lifecycle=lifecycle,
            vault=vault,
            config=config,
            paths=_Paths(tmp_path),
            clock=clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        app = await factory(1, vault.generation)
        started = await app.start(
            StartRequest.model_validate(
                {
                    **_COMMON,
                    "request_id": "req_00000000-0000-4000-8000-000000000101",
                    "mode": "create",
                    "task_title": "Replay a suspended check after the repository grant",
                    # A required review needs the user's request, not just the title (#908);
                    # without it the replay stops at the specification preflight instead.
                    "task_statement": (
                        "Replay the suspended required check after the repository grant and "
                        "reach its terminal result under the same request identity."
                    ),
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        frontier = started.frontier
        for request_id, drafts in _event_batches():
            published = await app.publish_work(
                PublishWorkRequest.model_validate(
                    {
                        **_COMMON,
                        "request_id": request_id,
                        "session_id": started.session_id,
                        "writer_id": started.writer_id,
                        "expected_frontier": {
                            "sequence": str(frontier.sequence),
                            "head_digest": frontier.head_digest,
                        },
                        "event_drafts": drafts,
                    }
                ),
                repository_privacy_context=_REPOSITORY,
            )
            assert published.ok is True
            frontier = published.result_frontier
        request = CheckRequest.model_validate(
            {
                **_COMMON,
                "request_id": _CHECK_REQUEST_ID,
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": {
                    "sequence": str(frontier.sequence),
                    "head_digest": frontier.head_digest,
                },
                "mode": "semantic_required",
                "max_findings": "3",
                "policy_packs": ["work-integrity/0.3.0"],
            }
        )

        suspended = await app.check(request, repository_privacy_context=_REPOSITORY)
        assert type(suspended) is CheckAwaitingHuman
        assert suspended.continuation.kind == "repository_privacy_setup"
        assert suspended.continuation.request_id == _CHECK_REQUEST_ID

        await _grant_repository_policy(app, vault, clock)
        if "credential" in variant:
            await _store_provider_credential(vault, memory, provider)
        if "restart" in variant:
            # A service re-ready between the ceremony and the replay reopens the bundle and
            # rehydrates the pending check from its durable resume checkpoint.
            await app.close()
            app = None
            app = await factory(2, vault.generation)
        clock.now = clock.now.replace(minute=12)

        replayed = await app.check(request, repository_privacy_context=_REPOSITORY)
        assert type(replayed) is CheckCommitResult, replayed
        assert replayed.request_id == _CHECK_REQUEST_ID
        assert replayed.outcome == "committed"
        assert replayed.subject_frontier == frontier
        # The grant was consumed: the check is past the standing-grant fence either way, and the
        # only remaining reasons are provider-side, never a policy or storage verdict.
        assert replayed.semantic_status.value in {"unavailable", "failed", "succeeded"}
        assert replayed.semantic_reason.value != "human_approval_required"
        assert replayed.semantic_reason.value != "scope_not_authorized"

        # Exact same-request replay of the terminal result is idempotent.
        again = await app.check(request, repository_privacy_context=_REPOSITORY)
        assert type(again) is CheckCommitResult
        assert again.outcome == "replayed"
        assert again.result_frontier == replayed.result_frontier

        status = await app.status(
            StatusRequest.model_validate(
                {
                    **_COMMON,
                    "request_id": "req_00000000-0000-4000-8000-000000000428",
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "view": "operation",
                    "limit": "1",
                    "filter": {"operation_request_id": _CHECK_REQUEST_ID},
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        page = status.page
        assert getattr(page, "state", None) == "complete", page
        assert getattr(page, "continuation", None) is None
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()
