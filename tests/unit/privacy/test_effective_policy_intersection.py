"""RT-privacy-egress-3: effective_policy intersects ancestor scopes (ADR-009)."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import apsw
import pytest

from finishup.adapters.memory.privacy import MemoryPrivacyCatalogState, MemoryPrivacyPolicyStore
from finishup.adapters.privacy.catalog import CatalogPrivacyPolicyStore
from finishup.adapters.sqlite.start_catalog import SqliteStartCatalog
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ChannelPolicy,
    DataClass,
    EgressChannel,
    PolicyOverlay,
    PrivacyPolicy,
    PrivacyProfile,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.models import DataCategory

_NOW = datetime(2026, 8, 3, tzinfo=UTC)
_INSTALLATION = "ins_30000000-0000-4000-8000-000000000001"
_WORKSPACE = f"hmac-sha256:{'6' * 64}"
_TASK = "tsk_30000000-0000-4000-8000-00000000000b"
_POLICY_M = "pvy_30000000-0000-4000-8000-000000000006"
_POLICY_W = "pvy_30000000-0000-4000-8000-000000000007"
_DIGEST_M = f"sha256:{'1' * 64}"
_DIGEST_W = f"sha256:{'2' * 64}"
_WORKSPACE_B = f"hmac-sha256:{'7' * 64}"
_TASK_B = "tsk_30000000-0000-4000-8000-00000000000c"
_ROUTE_A = f"sha256:{'8' * 64}"
_ROUTE_B = f"sha256:{'9' * 64}"


class _Clock:
    def now_utc(self) -> datetime:
        return _NOW

    def monotonic_seconds(self) -> float:
        return 1.0


class _Ids:
    def new(self, _kind: object) -> str:
        return "svc_30000000-0000-4000-8000-00000000000d"


class _Lookup:
    def mac(self, _domain: bytes, _message: bytes) -> str:
        raise AssertionError("legacy route binding does not commit new identity input")


def _database() -> apsw.Connection:
    db = apsw.Connection(":memory:")
    db.execute(Path("migrations/catalog/0001.sql").read_text(encoding="utf-8"))
    return db


def _disabled(channel: EgressChannel) -> ChannelPolicy:
    return ChannelPolicy(
        channel,
        False,
        (),
        (),
        None,
        (),
        AuthorizationScopeKind.MACHINE,
        False,
        0,
        0,
        0,
    )


def _ordered(channels: dict[EgressChannel, ChannelPolicy]) -> tuple[ChannelPolicy, ...]:
    return tuple(
        channels[channel] for channel in sorted(EgressChannel, key=lambda item: item.value)
    )


def _local_only(*, scope: AuthorizationScope, policy_id: str, digest: str) -> PrivacyPolicy:
    return PrivacyPolicy(
        policy_id,
        1,
        digest,
        PrivacyProfile.LOCAL_ONLY,
        ReviewContextProfile.STRUCTURAL,
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        False,
        False,
        scope,
        _ordered({channel: _disabled(channel) for channel in EgressChannel}),
        False,
        None,
        (),
        (),
        (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        (DataClass.PUBLIC_STRUCTURAL,),
        tuple(DataCategory),
        (
            DataClass.ORDINARY_USER_CONTENT,
            DataClass.PUBLIC_STRUCTURAL,
            DataClass.SENSITIVE_CONFIDENTIAL,
        ),
        _NOW,
    )


def _minimal_external(
    *,
    scope: AuthorizationScope,
    policy_id: str,
    digest: str,
    scope_ceiling: AuthorizationScopeKind = AuthorizationScopeKind.TASK,
    max_bytes: int = 262_144,
) -> PrivacyPolicy:
    channels = {channel: _disabled(channel) for channel in EgressChannel}
    channels[EgressChannel.LLM_INFERENCE] = ChannelPolicy(
        EgressChannel.LLM_INFERENCE,
        True,
        (
            DataCategory.BOUNDED_STRUCTURAL_METADATA,
            DataCategory.TASK_DESCRIPTION,
        ),
        (DataClass.ORDINARY_USER_CONTENT, DataClass.PUBLIC_STRUCTURAL),
        ProviderBinding(
            "fireworks",
            "accounts/fireworks/models/minimax-m3",
            "fireworks-responses",
            "1.0.0",
            "external",
        ),
        ("semantic-review",),
        scope_ceiling,
        False,
        max_bytes,
        4096,
        300,
    )
    return PrivacyPolicy(
        policy_id,
        2,
        digest,
        PrivacyProfile.MINIMAL_EXTERNAL,
        ReviewContextProfile.ASSISTED,
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED),
        False,
        True,
        scope,
        _ordered(channels),
        False,
        None,
        (),
        (),
        (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        (DataClass.PUBLIC_STRUCTURAL,),
        tuple(DataCategory),
        (
            DataClass.ORDINARY_USER_CONTENT,
            DataClass.PUBLIC_STRUCTURAL,
            DataClass.SENSITIVE_CONFIDENTIAL,
        ),
        _NOW,
    )


def _task_scope() -> AuthorizationScope:
    return AuthorizationScope(
        AuthorizationScopeKind.TASK,
        _INSTALLATION,
        _WORKSPACE,
        _TASK,
    )


def _workspace_scope() -> AuthorizationScope:
    return AuthorizationScope(AuthorizationScopeKind.WORKSPACE, _INSTALLATION, _WORKSPACE)


def _machine_scope() -> AuthorizationScope:
    return AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION)


def _llm_authorized(policy: PrivacyPolicy) -> bool:
    llm = next(
        channel
        for channel in policy.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )
    return policy.network_egress_permitted and llm.enabled


def _overlay(policy: PrivacyPolicy) -> PolicyOverlay:
    return PolicyOverlay(
        policy.effective_scope,
        policy.review_selection,
        policy.require_current_provider_data_use_evidence,
        policy.channel_policies,
        policy.local_model_categories,
        policy.local_model_data_classes,
        policy.agent_context_categories,
        policy.agent_context_data_classes,
        policy,
    )


@pytest.mark.parametrize("store_kind", ["catalog", "memory"])
def test_effective_policy_intersects_machine_ceiling_with_workspace_overlay(
    store_kind: str,
) -> None:
    machine = _local_only(scope=_machine_scope(), policy_id=_POLICY_M, digest=_DIGEST_M)
    workspace = _minimal_external(scope=_workspace_scope(), policy_id=_POLICY_W, digest=_DIGEST_W)

    async def run() -> PrivacyPolicy:
        if store_kind == "catalog":
            store: CatalogPrivacyPolicyStore | MemoryPrivacyPolicyStore = CatalogPrivacyPolicyStore(
                _database(), _Clock()
            )
        else:
            store = MemoryPrivacyPolicyStore(MemoryPrivacyCatalogState(), _Clock())
        await store.seed_if_absent(machine)
        await store.seed_if_absent(workspace)
        effective = await store.effective_policy(_task_scope())
        return effective.policy

    policy = asyncio.run(run())
    assert not _llm_authorized(policy), (
        "effective_policy must meet machine local_only with workspace external, "
        f"not select workspace alone; profile={policy.profile.value} "
        f"scope={policy.effective_scope.kind.value} llm_authorized={_llm_authorized(policy)}"
    )
    assert policy.profile is PrivacyProfile.LOCAL_ONLY
    assert policy.network_egress_permitted is False


def test_privacy_policy_meet_is_commutative_for_local_and_external() -> None:
    machine = _local_only(scope=_machine_scope(), policy_id=_POLICY_M, digest=_DIGEST_M)
    workspace = _minimal_external(scope=_workspace_scope(), policy_id=_POLICY_W, digest=_DIGEST_W)
    left = machine.meet(workspace)
    right = workspace.meet(machine)
    assert left.network_egress_permitted is False
    assert right.network_egress_permitted is False
    assert left.profile is PrivacyProfile.LOCAL_ONLY
    assert right.profile is PrivacyProfile.LOCAL_ONLY
    assert _llm_authorized(left) is False
    assert _llm_authorized(right) is False


def _llm(policy: PrivacyPolicy) -> ChannelPolicy:
    return next(
        channel
        for channel in policy.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )


def test_legacy_repository_carry_forward_is_bounded_by_migration_frontier() -> None:
    machine_scope = _machine_scope()
    frontier = _minimal_external(
        scope=machine_scope,
        policy_id=_POLICY_M,
        digest=_DIGEST_M,
        max_bytes=1_000,
    )
    widened = replace(
        _minimal_external(
            scope=machine_scope,
            policy_id=_POLICY_M,
            digest=f"sha256:{'3' * 64}",
            max_bytes=2_000,
        ),
        version=3,
        supersedes_policy_digest=frontier.policy_digest,
    )
    scopes = (
        AuthorizationScope(AuthorizationScopeKind.WORKSPACE, _INSTALLATION, _WORKSPACE),
        AuthorizationScope(AuthorizationScopeKind.WORKSPACE, _INSTALLATION, _WORKSPACE_B),
    )
    routes = tuple(
        (
            task_id,
            canonical_digest(
                {
                    "task_id": task_id,
                    "bundle_relpath": f"tasks/{task_id}",
                    "route_generation": 1,
                }
            ),
        )
        for task_id in (_TASK, _TASK_B)
    )

    async def run_catalog() -> tuple[object, object]:
        db = _database()
        store = CatalogPrivacyPolicyStore(db, _Clock())
        await store.seed_if_absent(frontier)
        for index, (task_id, route_digest) in enumerate(routes):
            db.execute(
                """INSERT INTO task_routes (
                       task_id, workspace_ref_commitment, external_ref_commitment,
                       active_session_id, bundle_relpath, route_generation,
                       active_route_identity_digest, state, quarantine_code, created_at, updated_at
                   ) VALUES (?, NULL, NULL, ?, ?, 1, ?, 'active', NULL, ?, ?)""",
                (
                    task_id,
                    f"ses_30000000-0000-4000-8000-{index + 20:012x}",
                    f"tasks/{task_id}",
                    route_digest,
                    "2026-08-03T00:00:00.000Z",
                    "2026-08-03T00:00:00.000Z",
                ),
            )
        for version in ("0002", "0003"):
            db.execute(Path(f"migrations/catalog/{version}.sql").read_text(encoding="utf-8"))
        await store.tighten(machine_scope, _overlay(widened), frontier.policy_digest)
        start_catalog = SqliteStartCatalog(
            db,
            installation_id=_INSTALLATION,
            lookup=_Lookup(),  # type: ignore[arg-type]
            clock=_Clock(),
            ids=_Ids(),  # type: ignore[arg-type]
        )
        authorities: list[object] = []
        for scope, (task_id, route_digest) in zip(scopes, routes, strict=True):
            await start_catalog.bind_repository_privacy(
                task_id,
                route_digest,
                scope.workspace_ref_commitment,  # type: ignore[arg-type]
            )
            authorities.append(await store.repository_authority(scope))
        return authorities[0], authorities[1]

    async def run_memory() -> tuple[object, object]:
        state = MemoryPrivacyCatalogState()
        store = MemoryPrivacyPolicyStore(state, _Clock())
        await store.seed_if_absent(frontier)
        state.first_repository_carry_forward_state = "not_applicable"
        state.migration_frontier_policy = frontier
        state.legacy_route_entitlements = {route: frontier for route in routes}
        await store.tighten(machine_scope, _overlay(widened), frontier.policy_digest)
        authorities = [
            await store.carry_forward_repository_authority(
                scope, task_id=task_id, route_identity_digest=route_digest
            )
            for scope, (task_id, route_digest) in zip(scopes, routes, strict=True)
        ]
        return authorities[0], authorities[1]

    for authorities in (asyncio.run(run_catalog()), asyncio.run(run_memory())):
        for authority in authorities:
            assert authority.migration_state == "consumed"  # type: ignore[attr-defined]
            assert authority.grant_policy is not None  # type: ignore[attr-defined]
            assert _llm(authority.grant_policy).max_bytes == 1_000  # type: ignore[attr-defined]


@pytest.mark.parametrize("with_route", [False, True])
def test_memory_failed_carry_forward_preserves_entitlement_history(with_route: bool) -> None:
    machine = _minimal_external(scope=_machine_scope(), policy_id=_POLICY_M, digest=_DIGEST_M)
    unavailable_frontier = _local_only(
        scope=_machine_scope(),
        policy_id=_POLICY_M,
        digest=f"sha256:{'a' * 64}",
    )
    state = MemoryPrivacyCatalogState(
        first_repository_carry_forward_state="not_applicable" if with_route else "available",
        migration_frontier_policy=unavailable_frontier,
        legacy_route_entitlements=({(_TASK, _ROUTE_A): unavailable_frontier} if with_route else {}),
    )
    store = MemoryPrivacyPolicyStore(state, _Clock())

    async def run() -> None:
        await store.seed_if_absent(machine)
        with pytest.raises(ValueError, match="repository_privacy_migration_unavailable"):
            await store.carry_forward_repository_authority(
                _workspace_scope(),
                task_id=_TASK if with_route else None,
                route_identity_digest=_ROUTE_A if with_route else None,
            )

    asyncio.run(run())
    assert state.first_repository_carry_forward_state == (
        "not_applicable" if with_route else "available"
    )
    assert state.legacy_route_entitlements == (
        {(_TASK, _ROUTE_A): unavailable_frontier} if with_route else {}
    )
    assert state.consumed_legacy_repository_commitments == set()
    assert state.generation == 1
    assert len(state.policies) == 1


def test_meet_keeps_the_narrower_scope_ceiling() -> None:
    """A lower scope rank is a *broader* ceiling, so the meet must keep the higher-ranked one.

    ``machine`` is the widest authorization ceiling a channel can carry and ``request`` the
    narrowest — the widen/tighten ceremony classifies ``task -> machine`` as
    ``scope_ceiling_broadened``. Intersecting a machine ceiling with a task ceiling must
    therefore yield ``task``, never ``machine``.
    """

    wide = _minimal_external(
        scope=_machine_scope(),
        policy_id=_POLICY_M,
        digest=_DIGEST_M,
        scope_ceiling=AuthorizationScopeKind.MACHINE,
    )
    narrow = _minimal_external(
        scope=_workspace_scope(),
        policy_id=_POLICY_W,
        digest=_DIGEST_W,
        scope_ceiling=AuthorizationScopeKind.TASK,
    )
    assert _llm(wide.meet(narrow)).scope_ceiling is AuthorizationScopeKind.TASK
    assert _llm(narrow.meet(wide)).scope_ceiling is AuthorizationScopeKind.TASK


def test_meet_keeps_the_smaller_byte_ceiling() -> None:
    wide = _minimal_external(
        scope=_machine_scope(), policy_id=_POLICY_M, digest=_DIGEST_M, max_bytes=262_144
    )
    narrow = _minimal_external(
        scope=_workspace_scope(), policy_id=_POLICY_W, digest=_DIGEST_W, max_bytes=1024
    )
    assert _llm(wide.meet(narrow)).max_bytes == 1024
    assert _llm(narrow.meet(wide)).max_bytes == 1024


@pytest.mark.parametrize("store_kind", ["catalog", "memory"])
def test_effective_generation_tracks_the_most_specific_row(store_kind: str) -> None:
    """The reported generation is the CAS token the transition path checks against the exact row.

    ``prepare_transition``/``commit_transition`` compare ``expected_generation`` against
    ``_current_exact(scope)``. Reporting a composed maximum across ancestors would make every
    transition at that scope fail ``privacy_policy_stale`` once an ancestor outran it.
    """

    machine = _local_only(scope=_machine_scope(), policy_id=_POLICY_M, digest=_DIGEST_M)
    workspace = _minimal_external(scope=_workspace_scope(), policy_id=_POLICY_W, digest=_DIGEST_W)

    async def run() -> tuple[int, int]:
        if store_kind == "catalog":
            store: CatalogPrivacyPolicyStore | MemoryPrivacyPolicyStore = CatalogPrivacyPolicyStore(
                _database(), _Clock()
            )
        else:
            store = MemoryPrivacyPolicyStore(MemoryPrivacyCatalogState(), _Clock())
        await store.seed_if_absent(machine)
        await store.seed_if_absent(workspace)
        effective = await store.effective_policy(_task_scope())
        exact = await store.effective_policy(_workspace_scope())
        return effective.generation, exact.generation

    composed_generation, workspace_generation = asyncio.run(run())
    assert composed_generation == workspace_generation
