"""A second repository after the first repository's hybrid grant (ADR-049, review round 2).

On a fresh install the installation row is unset with its inference channel off. Repository A's
first grant, with the recommended hybrid answer, turns that row's inference channel on. Round 1
kept the row's setting unset, so every repository without a grant of its own (a second project,
an independent clone of A) read the released "every task" setting: its checks that named no mode
suspended on the repository-grant handoff, a switch to local was ignored, and status claimed every
task runs with AI-powered review.

Now the installation row carries the hybrid too, and a repository without its own grant reads
"AI-powered review is not set up" (``ai_review_available`` false): its checks complete locally
and an agent's opt-in there says why it stays local. The full ready composition runs (SQLite
ledgers, encrypted objects, the catalog privacy store, a bound provider with its credential).
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from builders.privacy_policies import minimal_external_policy
from finishup.adapters.keys.encrypted_vault import EncryptedVaultStore
from finishup.adapters.keys.secret_memory import LocalSecretMemory
from finishup.application.privacy_policy import (
    DecidePrivacyPolicyRequest,
    PolicyDecisionRequired,
    ProposePrivacyPolicyRequest,
    decide_privacy_policy,
    privacy_propose_policy,
)
from finishup.application.service import Application
from finishup.config.models import FinishUpConfig
from finishup.config.write import fireworks_provider
from finishup.domain.events import CheckReviewMode, ReviewMode
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ConversationReview,
    EgressChannel,
)
from finishup.ports.control import RepositoryPrivacyContext, ServiceState
from finishup.ports.ledger import CheckCommitResult
from finishup.ports.privacy import HumanAuthorityCapability, HumanPolicyDecision
from finishup.ports.secret_memory import SecretPurpose
from finishup.protocol.canonical import JsonValue, canonical_digest
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import CheckRequest, PublishWorkRequest, StartRequest, StatusRequest
from finishup.service.lifecycle import ServiceLifecycle
from finishup.service.ready_composition import build_ready_application_factory
from finishup.service.vault import VaultMode, VaultService
from integration.service.test_check_repository_grant_replay import (
    _COMMON,
    _INSTALLATION_ID,
    _INSTANCE_ID,
    _Clock,
    _Diagnostics,
    _GenerationStore,
    _Paths,
    _private_paths,  # noqa: F401  # pyright: ignore[reportUnusedImport] - autouse fixture
    _store_provider_credential,
)

pytestmark = pytest.mark.anyio

_REPO_A = RepositoryPrivacyContext("hmac-sha256:" + "a" * 64, "git_common_root")
_REPO_B = RepositoryPrivacyContext("hmac-sha256:" + "b" * 64, "git_common_root")
# An independent clone of A is a different repository commitment (its own git common root).
_CLONE_OF_A = RepositoryPrivacyContext("hmac-sha256:" + "c" * 64, "git_common_root")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def _grant(
    app: Application,
    vault: VaultService,
    clock: _Clock,
    repository: RepositoryPrivacyContext,
    setting: ConversationReview,
) -> None:
    """The trusted ceremony for one repository's first grant, with the owner's setup answer."""

    policy_app = app.privacy.policy_application
    assert policy_app is not None
    scope = AuthorizationScope(
        AuthorizationScopeKind.WORKSPACE, _INSTALLATION_ID, repository.commitment
    )
    authority = await policy_app.policy_store.repository_authority(scope)
    assert authority.grant_state == "missing"
    candidate = replace(
        minimal_external_policy(),
        effective_scope=scope,
        created_at=clock.now_utc(),
        conversation_review=setting,
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


class _Task:
    def __init__(self, app: Application, repository: RepositoryPrivacyContext) -> None:
        self.app = app
        self.repository = repository
        self.started: object = None
        self.frontier: object = None

    def _ids(self) -> dict[str, JsonValue]:
        return {
            **_COMMON,
            "request_id": new_id(IdKind.REQUEST),
            "session_id": getattr(self.started, "session_id"),
            "writer_id": getattr(self.started, "writer_id"),
            "expected_frontier": {
                "sequence": str(getattr(self.frontier, "sequence")),
                "head_digest": getattr(self.frontier, "head_digest"),
            },
        }

    async def start(self, title: str) -> _Task:
        self.started = await self.app.start(
            StartRequest.model_validate(
                {
                    **_COMMON,
                    "request_id": new_id(IdKind.REQUEST),
                    "mode": "create",
                    "task_title": title,
                    "task_statement": f"{title}: change the parser and keep its tests green.",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=self.repository,
        )
        self.frontier = getattr(self.started, "frontier")
        return self

    async def switch(self, mode: ReviewMode) -> None:
        published = await self.app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **self._ids(),
                    "event_drafts": [
                        {
                            "event_id": new_id(IdKind.EVENT),
                            "schema": {"name": "decision_recorded", "version": "1.1.0"},
                            "occurred_at": "2026-08-27T17:06:00.000Z",
                            "causal_parents": [],
                            "payload": {
                                "statement": "Switch this task's review mode.",
                                "rationale": "Regression test.",
                                "authority": "harness:pytest",
                                "review_mode": mode.value,
                            },
                            "artifact_refs": [],
                            "evidence_refs": [],
                        }
                    ],
                }
            ),
            repository_privacy_context=self.repository,
        )
        assert published.ok is True
        self.frontier = published.result_frontier

    async def check(self) -> CheckCommitResult:
        # No mode: the check runs in the task's review mode.
        result = await self.app.check(
            CheckRequest.model_validate({**self._ids(), "max_findings": "3"}),
            repository_privacy_context=self.repository,
        )
        assert type(result) is CheckCommitResult, result
        self.frontier = result.result_frontier
        return result

    async def review_mode(self) -> Mapping[str, object]:
        body = {**self._ids(), "view": "compact", "limit": "1"}
        body.pop("expected_frontier")
        status = await self.app.status(
            StatusRequest.model_validate(body), repository_privacy_context=self.repository
        )
        return cast(Mapping[str, object], cast(dict[str, object], status.as_json())["review_mode"])


@pytest.mark.parametrize("repository", [_REPO_B, _CLONE_OF_A], ids=["second_repo", "clone_of_a"])
async def test_an_ungranted_repository_stays_local_after_the_first_hybrid_grant(
    tmp_path: Path, repository: RepositoryPrivacyContext
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
    config = FinishUpConfig(profile="local-openai", provider=provider)
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
        policy_app = app.privacy.policy_application
        assert policy_app is not None
        machine_scope = AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION_ID)
        seeded = (await policy_app.policy_store.effective_policy(machine_scope)).policy
        # A fresh install: the installation row is unset and sends nothing for review.
        assert seeded.conversation_review is None
        assert not next(
            item for item in seeded.channel_policies if item.channel is EgressChannel.LLM_INFERENCE
        ).enabled

        await _grant(app, vault, clock, _REPO_A, ConversationReview.LOCAL_AGENT_OPT_IN)
        await _store_provider_credential(vault, memory, provider)
        machine = (await policy_app.policy_store.effective_policy(machine_scope)).policy
        assert machine.conversation_review is ConversationReview.LOCAL_AGENT_OPT_IN

        # Repository A: the hybrid, with AI-powered review available.
        task_a = await (_Task(app, _REPO_A)).start("Repository A task")
        a_mode = await task_a.review_mode()
        assert (a_mode["setting"], a_mode["ai_review_available"]) == ("local_agent_opt_in", True)

        # Repository B (or an independent clone of A): no grant of its own.
        task = await (_Task(app, repository)).start("Second repository task")
        mode = await task.review_mode()
        assert mode["mode"] == "local"
        assert mode["setting"] == "local_agent_opt_in"
        assert mode["setting_explicit"] is True
        assert mode["ai_review_available"] is False
        checked = await task.check()
        assert checked.review_mode == CheckReviewMode(ReviewMode.LOCAL, "conversation_default")

        # A switch to local is honoured (and changes nothing here); an opt-in says why it
        # stays local instead of suspending on the repository-grant handoff.
        await task.switch(ReviewMode.LOCAL)
        after_local = await task.check()
        assert after_local.review_mode is not None
        assert after_local.review_mode.mode is ReviewMode.LOCAL
        await task.switch(ReviewMode.AI_POWERED)
        opted = await task.check()
        assert opted.review_mode is not None
        assert opted.review_mode.local_reason == "ai_review_not_set_up"
        assert (await task.review_mode())["local_reason"] == "ai_review_not_set_up"
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()
