"""Default LOCAL_ONLY agent-context allowlist includes verification projection content."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import apsw
import pytest

from finishup.adapters.privacy.catalog import CatalogPrivacyPolicyStore
from finishup.domain.privacy import (
    AuthorizationScope,
    DataCategory,
    DataClass,
    PolicyOverlay,
    PrivacyPolicy,
)
from finishup.service import ready_composition as ready_composition_module

_INSTALLATION = "ins_00000000-0000-4000-8000-000000000001"
_POLICY_ID = "pvy_00000000-0000-4000-8000-000000000001"
_CREATED_AT = datetime(2026, 7, 24, tzinfo=UTC)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _seed_digest(*, revision: str | None) -> str:
    return ready_composition_module._bootstrap_seed_digest(  # pyright: ignore[reportPrivateUsage]
        _INSTALLATION, revision=revision
    )


def _current_default() -> PrivacyPolicy:
    return ready_composition_module._denied_policy(  # pyright: ignore[reportPrivateUsage]
        installation_id=_INSTALLATION,
        policy_id=_POLICY_ID,
        policy_digest=_seed_digest(
            revision=ready_composition_module._BOOTSTRAP_DEFAULT_REVISION  # pyright: ignore[reportPrivateUsage]
        ),
        created_at=_CREATED_AT,
    )


def _legacy_default() -> PrivacyPolicy:
    """Reproduce the exact pre-ADR-009 shipped default, including its bootstrap seed digest."""

    base = _current_default()
    return ready_composition_module._shipped_default_policy(  # pyright: ignore[reportPrivateUsage]
        base, revision=None
    )


class _RecordingStore:
    """Captures the re-seed call so the upgrade decision is observable without a database."""

    def __init__(self, stored: PrivacyPolicy) -> None:
        self.stored = stored
        self.calls: list[tuple[PrivacyPolicy, PrivacyPolicy]] = []

    async def reseed_untouched_bootstrap_default(
        self,
        scope: AuthorizationScope,
        *,
        expected_current: PrivacyPolicy,
        replacement: PrivacyPolicy,
    ) -> PrivacyPolicy:
        del scope
        self.calls.append((expected_current, replacement))
        return replacement


def test_default_local_only_allows_receipt_projection_categories() -> None:
    from finishup.domain.privacy import EgressChannel

    policy = _current_default()
    assert DataCategory.FINDING_SUMMARY in policy.agent_context_categories
    assert DataCategory.OBLIGATION_TEXT in policy.agent_context_categories
    assert DataCategory.BOUNDED_STRUCTURAL_METADATA in policy.agent_context_categories
    assert DataClass.ORDINARY_USER_CONTENT in policy.agent_context_data_classes
    assert DataClass.PUBLIC_STRUCTURAL in policy.agent_context_data_classes
    # Observation-derived / vault-adjacent categories stay off the default allowlist.
    assert DataCategory.REPOSITORY_EXCERPT not in policy.agent_context_categories
    assert DataCategory.TRANSCRIPT_EXCERPT not in policy.agent_context_categories
    # Product default: structural package update checks on, LLM off, local_only.
    assert policy.network_egress_permitted is True
    updates = next(
        row for row in policy.channel_policies if row.channel is EgressChannel.UPDATE_CHECKS
    )
    llm = next(row for row in policy.channel_policies if row.channel is EgressChannel.LLM_INFERENCE)
    assert updates.enabled is True
    assert llm.enabled is False


@pytest.mark.anyio
async def test_untouched_legacy_default_is_carried_forward() -> None:
    """An installation seeded before the widening must not keep unreadable receipts forever."""

    stored = _legacy_default()
    store = _RecordingStore(stored)
    scope = stored.effective_scope

    result = await ready_composition_module._reseed_untouched_default_policy(  # pyright: ignore[reportPrivateUsage]
        store,  # pyright: ignore[reportArgumentType]
        scope,
        stored,
    )

    assert len(store.calls) == 1
    expected_current, replacement = store.calls[0]
    assert expected_current == stored
    assert result == replacement
    assert DataCategory.FINDING_SUMMARY in result.agent_context_categories
    assert DataClass.ORDINARY_USER_CONTENT in result.agent_context_data_classes
    # A superseding version is written, never an in-place rewrite of the recorded policy.
    assert replacement.version == stored.version + 1
    # Different contents must never share one policy_digest: it is the CAS precondition for
    # later tightenings and is published as the effective policy digest.
    assert replacement.policy_digest != stored.policy_digest
    assert replacement.policy_digest == _current_default().policy_digest


@pytest.mark.anyio
async def test_owner_edited_policy_is_never_reseeded() -> None:
    """Any owner edit must survive upgrade; only the exact untouched old default is replaced."""

    edited = replace(
        _legacy_default(),
        agent_context_categories=(DataCategory.BOUNDED_STRUCTURAL_METADATA,),
    )
    store = _RecordingStore(edited)

    result = await ready_composition_module._reseed_untouched_default_policy(  # pyright: ignore[reportPrivateUsage]
        store,  # pyright: ignore[reportArgumentType]
        edited.effective_scope,
        edited,
    )

    assert store.calls == []
    assert result is edited


@pytest.mark.anyio
async def test_current_default_is_left_alone() -> None:
    """A policy already carrying the current default needs no write on every ready build."""

    stored = _current_default()
    store = _RecordingStore(stored)

    result = await ready_composition_module._reseed_untouched_default_policy(  # pyright: ignore[reportPrivateUsage]
        store,  # pyright: ignore[reportArgumentType]
        stored.effective_scope,
        stored,
    )

    assert store.calls == []
    assert result is stored


class _Clock:
    def now_utc(self) -> datetime:
        return _CREATED_AT

    def monotonic_seconds(self) -> float:
        return 1.0


def _database() -> apsw.Connection:
    db = apsw.Connection(":memory:")
    db.execute(Path("migrations/catalog/0001.sql").read_text(encoding="utf-8"))
    return db


def _store(db: apsw.Connection) -> CatalogPrivacyPolicyStore:
    return CatalogPrivacyPolicyStore(db, _Clock())  # pyright: ignore[reportArgumentType]


def _overlay(candidate: PrivacyPolicy) -> PolicyOverlay:
    return PolicyOverlay(
        candidate.effective_scope,
        candidate.review_selection,
        candidate.require_current_provider_data_use_evidence,
        candidate.channel_policies,
        candidate.local_model_categories,
        candidate.local_model_data_classes,
        candidate.agent_context_categories,
        candidate.agent_context_data_classes,
        candidate,
    )


def test_store_reseeds_only_a_row_with_first_run_seed_provenance() -> None:
    """The durable store must swap the untouched first-run seed and nothing else."""

    db = _database()
    store = _store(db)
    legacy = _legacy_default()
    replacement = replace(_current_default(), version=legacy.version + 1)

    async def run() -> PrivacyPolicy:
        await store.seed_if_absent(legacy)
        return await store.reseed_untouched_bootstrap_default(
            legacy.effective_scope, expected_current=legacy, replacement=replacement
        )

    result = asyncio.run(run())

    assert result == replacement
    assert db.execute(
        "SELECT state, change_kind FROM privacy_policy_versions ORDER BY policy_generation"
    ).fetchall() == [("superseded", "seed"), ("current", "seed")]


def test_store_leaves_an_owner_chosen_policy_with_legacy_contents_alone() -> None:
    """Contents cannot prove origin: an owner tightening to the old fields must survive."""

    db = _database()
    store = _store(db)
    # The owner narrows the current default back to exactly the pre-ADR-009 agent-context
    # allowlist. Its contents equal the old shipped default, but its provenance does not.
    owner_chosen = replace(_legacy_default(), version=2)

    async def run() -> PrivacyPolicy:
        seeded = await store.seed_if_absent(_current_default())
        await store.tighten(
            owner_chosen.effective_scope, _overlay(owner_chosen), seeded.policy_digest
        )
        return await store.reseed_untouched_bootstrap_default(
            owner_chosen.effective_scope,
            expected_current=owner_chosen,
            replacement=replace(_current_default(), version=3),
        )

    result = asyncio.run(run())

    assert result == owner_chosen
    assert DataCategory.FINDING_SUMMARY not in result.agent_context_categories
    assert db.execute(
        "SELECT state, change_kind FROM privacy_policy_versions ORDER BY policy_generation"
    ).fetchall() == [("superseded", "seed"), ("current", "tightening")]
