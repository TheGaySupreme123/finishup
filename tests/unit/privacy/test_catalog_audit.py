"""Durable provider-free privacy catalog tests."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import apsw
import pytest

from builders.privacy_policies import minimal_external_policy
from finishup.adapters.memory.privacy import (
    MemoryPrivacyAudit,
    MemoryPrivacyCatalogState,
    MemoryPrivacyPolicyStore,
)
from finishup.adapters.privacy.catalog import (  # pyright: ignore[reportPrivateUsage]
    _LOOKUP_DOMAIN,  # pyright: ignore[reportPrivateUsage]
    CatalogPrivacyAudit,
    CatalogPrivacyPolicyStore,
    _mac,  # pyright: ignore[reportPrivateUsage]
)
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.observation_advice_semantic import (
    SqliteObservationAdviceSemanticRepository,
)
from finishup.application.egress import (
    PrivacyCoordinator,
    SemanticEgressAttemptUnknown,
    SemanticEgressAwaitingHuman,
)
from finishup.application.observation_advice_semantic import (
    ObservationAdviceSemanticAttempt,
    ObservationAdviceSemanticOutcome,
    ObservationAdviceSemanticWorker,
)
from finishup.domain.privacy import (
    MAX_WITHHELD_ITEM_IDS,
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    ChannelPolicy,
    ConsentSource,
    DataClass,
    EgressAuthorization,
    EgressChannel,
    EgressReceipt,
    LocalDisclosureApproved,
    LocalDisclosureReceipt,
    LocalDisclosureSink,
    PrivacyOutcome,
    PrivacyPolicy,
    PrivacyProfile,
    PrivacyReason,
    ProjectionAuditContext,
    ProviderBinding,
    ReceiptCounts,
    ReceiptPolicyBinding,
    ReceiptSecretScan,
    ReceiptSecretScanStage,
    ReceiptTransformations,
    RequestCommitment,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.domain.values import format_rfc3339_millis
from finishup.ports.objects import (
    ObjectMetadata,
    ObjectRef,
    ObjectSource,
    ObjectStorePort,
    StagedObject,
)
from finishup.ports.privacy import (
    AgentProjectionRequest,
    CompletedAgentProjection,
    ConsumedAuthorization,
    DisclosureProposalRequest,
    HumanPolicyDecision,
    LocalDisclosureReceiptView,
    MinimizedDisclosure,
    NetworkEgressReceiptView,
    OutboundGatewayPort,
    PolicyOverlay,
    PolicyTransitionMember,
    PolicyTransitionProposal,
    PrivacyAuditPort,
    PrivacyAuditState,
    PrivacyAuditUnreadable,
    PrivacyClassifierPort,
    PrivacyPolicyStorePort,
    PrivacyReceiptAudience,
    PrivacyReceiptCursorInvalid,
    PrivacyReceiptPage,
    PrivacyReceiptQuery,
    PrivacyReceiptView,
)
from finishup.ports.semantic import Deadline
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.ids import IdKind
from finishup.protocol.models import DataCategory

_NOW = datetime(2026, 7, 19, tzinfo=UTC)
_INSTALLATION = "ins_30000000-0000-4000-8000-000000000001"
_REQUEST = "req_30000000-0000-4000-8000-000000000002"
_RPC = "rpc_30000000-0000-4000-8000-000000000003"
_SERVICE = "svc_30000000-0000-4000-8000-000000000004"
_PROPOSAL = "ppr_30000000-0000-4000-8000-000000000005"
_DISPATCH = "dsp_30000000-0000-4000-8000-000000000006"
_POLICY = "pvy_30000000-0000-4000-8000-000000000006"
_RECEIPT = "egr_30000000-0000-4000-8000-000000000007"
_DIGEST = f"sha256:{'3' * 64}"
_REQUEST_2 = "req_30000000-0000-4000-8000-000000000008"
_PROPOSAL_2 = "ppr_30000000-0000-4000-8000-000000000009"
_RECEIPT_2 = "egr_30000000-0000-4000-8000-00000000000a"
_TASK = "tsk_30000000-0000-4000-8000-00000000000b"
_SESSION = "ses_30000000-0000-4000-8000-00000000000c"
_OBJECT = "obj_30000000-0000-4000-8000-00000000000d"
_OBJECT_2 = "obj_30000000-0000-4000-8000-00000000000e"
_ROUTE_DIGEST = f"sha256:{'5' * 64}"
_WORKSPACE = f"hmac-sha256:{'6' * 64}"


class _Clock:
    def now_utc(self) -> datetime:
        return _NOW

    def monotonic_seconds(self) -> float:
        return 1.0


class _Key:
    def mac(self, domain: bytes, message: bytes) -> str:
        digest = hmac.new(b"k" * 32, domain + message, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"


class _UnusedObjects:
    def __getattr__(self, name: str) -> object:
        raise AssertionError(f"object store used by objectless projection: {name}")


class _Objects:
    async def stage(self, source: ObjectSource, metadata: ObjectMetadata) -> StagedObject:
        assert source.data is not None
        return StagedObject(
            _OBJECT,
            len(source.data),
            f"hmac-sha256:{'7' * 64}",
            f"sha256:{'8' * 64}",
            "yoetz-object/1",
            "privacy-slot",
            metadata,
            object(),
        )

    async def finalize(self, staged: StagedObject) -> ObjectRef:
        return ObjectRef(
            staged.object_id,
            staged.plaintext_size,
            staged.commitment,
            staged.envelope_digest,
            staged.encryption_format,
            staged.key_slot,
            staged.metadata,
        )


class _StoredObjects(_Objects):
    """Small proposal object store so the real Catalog adapter can reload a disclosure."""

    def __init__(self, object_ids: tuple[str, ...] = (_OBJECT,)) -> None:
        self._payloads: dict[str, bytes] = {}
        self._object_ids = object_ids
        self._stage_count = 0

    async def stage(self, source: ObjectSource, metadata: ObjectMetadata) -> StagedObject:
        assert source.data is not None
        staged = await super().stage(source, metadata)
        object_id = self._object_ids[min(self._stage_count, len(self._object_ids) - 1)]
        self._stage_count += 1
        staged = replace(staged, object_id=object_id)
        self._payloads[staged.object_id] = source.data
        return staged

    def open_verified(self, ref: ObjectRef) -> AsyncIterator[bytes]:
        async def chunks() -> AsyncIterator[bytes]:
            yield self._payloads[ref.object_id]

        return chunks()


class _Ids:
    def new(self, kind: IdKind) -> str:
        return _PROPOSAL if kind is IdKind.PRIVACY_PROPOSAL else _RECEIPT


class _Gateway:
    async def close(self) -> None:
        return None


def _database() -> apsw.Connection:
    db = apsw.Connection(":memory:")
    for version in ("0001", "0002", "0003"):
        db.execute(Path(f"migrations/catalog/{version}.sql").read_text(encoding="utf-8"))
    return db


def _scope() -> AuthorizationScope:
    return AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION)


def _task_scope() -> AuthorizationScope:
    return AuthorizationScope(AuthorizationScopeKind.TASK, _INSTALLATION, _WORKSPACE, _TASK)


def _insert_task_route(db: apsw.Connection) -> None:
    db.execute(
        """INSERT INTO task_routes (
               task_id, workspace_ref_commitment, external_ref_commitment,
               active_session_id, bundle_relpath, route_generation, active_route_identity_digest,
               state, quarantine_code, created_at, updated_at
           ) VALUES (?, NULL, NULL, ?, ?, 1, ?, 'active', NULL, ?, ?)""",
        (
            _TASK,
            _SESSION,
            f"tasks/{_TASK}",
            _ROUTE_DIGEST,
            _NOW.isoformat().replace("+00:00", "Z"),
            _NOW.isoformat().replace("+00:00", "Z"),
        ),
    )


def _external_disclosure_request() -> DisclosureProposalRequest:
    payload = canonical_encode({"semantic": "recovery-test"})
    minimized = MinimizedDisclosure(
        payload,
        ("item-1",),
        (_DIGEST,),
        (),
        (),
        (("removed_items", 0),),
        len(payload),
        1,
        _DIGEST,
        "scanner-v1",
        _DIGEST,
        (),
    )
    return DisclosureProposalRequest(
        _PROPOSAL,
        _REQUEST,
        _TASK,
        minimized,
        ProviderBinding("provider-test", "model-test", "endpoint-test", "1.0.0", "external"),
        None,
        "semantic-review",
        _task_scope(),
        _POLICY,
        1,
        1,
        _DIGEST,
        len(payload),
        1,
        _NOW + timedelta(minutes=1),
    )


def _receipt() -> LocalDisclosureReceipt:
    scope = _scope()
    return LocalDisclosureReceipt(
        "1.0.0",
        _RECEIPT,
        _REQUEST,
        _PROPOSAL,
        LocalDisclosureSink.AGENT_CONTEXT,
        PrivacyOutcome.COMPLETED,
        _NOW,
        scope,
        "client_result_projection",
        ReceiptPolicyBinding(_POLICY, 1, _DIGEST, canonical_digest({"scope": "machine"})),
        ConsentSource.BASELINE_POLICY,
        (),
        (),
        ReceiptCounts(0, 0, 0, 0, 0, 0, 2, 0, None),
        ReceiptTransformations(0, 0, 0),
        ReceiptSecretScan("scanner-v1", _DIGEST, 0, True),
        None,
        1,
    )


def _legacy_receipt_view(
    receipt: LocalDisclosureReceipt | EgressReceipt,
) -> LocalDisclosureReceipt | EgressReceipt:
    """Memory and SQLite expose the same uncertainty for released 1.0 receipt bytes."""

    return replace(
        receipt,
        secret_scan=replace(
            receipt.secret_scan,
            stage=ReceiptSecretScanStage.LEGACY_UNKNOWN,
            not_run_reason=None,
        ),
    )


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


def _policy(*, version: int = 1, digest: str = _DIGEST) -> PrivacyPolicy:
    return PrivacyPolicy(
        _POLICY,
        version,
        digest,
        PrivacyProfile.LOCAL_ONLY,
        ReviewContextProfile.STRUCTURAL,
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        False,
        False,
        _scope(),
        tuple(_disabled(channel) for channel in sorted(EgressChannel, key=lambda item: item.value)),
        False,
        None,
        (),
        (),
        (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        (DataClass.PUBLIC_STRUCTURAL,),
        tuple(DataCategory),
        (DataClass.ORDINARY_USER_CONTENT, DataClass.PUBLIC_STRUCTURAL),
        _NOW,
        None if version == 1 else _DIGEST,
    )


def _projection_request(
    proposal_id: str = _PROPOSAL, request_id: str = _REQUEST
) -> AgentProjectionRequest:
    empty = canonical_encode({})
    return AgentProjectionRequest(
        proposal_id,
        request_id,
        _RPC,
        "check",
        _SERVICE,
        1,
        None,
        empty,
        _scope(),
        None,
        None,
        _POLICY,
        1,
        1,
        _DIGEST,
        LocalDisclosureSink.AGENT_CONTEXT,
        (),
        empty,
        empty,
        (),
        0,
        0,
        0,
        _NOW,
    )


def test_objectless_projection_is_atomically_completed_and_queryable() -> None:
    db = _database()
    audit = CatalogPrivacyAudit(db, _UnusedObjects(), _Key(), _Clock())  # type: ignore[arg-type]
    request = _projection_request()

    async def run() -> tuple[
        CompletedAgentProjection, PrivacyReceiptView | None, PrivacyReceiptPage
    ]:
        completed = await audit.complete_agent_projection(request, _receipt())
        fetched = await audit.get_receipt(_RECEIPT, PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL)
        page = await audit.list_receipts(
            PrivacyReceiptQuery(), PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL
        )
        return completed, fetched, page

    completed, fetched, page = asyncio.run(run())

    assert completed.subject.projection_commitment.startswith("hmac-sha256:")
    assert fetched is not None
    assert page.receipts == (fetched,)
    row = db.execute(
        "SELECT state, content_object_id, receipt_id FROM privacy_audit_records"
    ).fetchone()
    assert row == ("local_disclosure_completed", None, _RECEIPT)


def test_policy_store_seed_effective_and_tightening_are_generation_cas() -> None:
    db = _database()
    store = CatalogPrivacyPolicyStore(db, _Clock())
    seed = _policy()
    tightened = _policy(version=2, digest=f"sha256:{'4' * 64}")
    overlay = PolicyOverlay(
        tightened.effective_scope,
        tightened.review_selection,
        tightened.require_current_provider_data_use_evidence,
        tightened.channel_policies,
        tightened.local_model_categories,
        tightened.local_model_data_classes,
        tightened.agent_context_categories,
        tightened.agent_context_data_classes,
        tightened,
    )

    async def run() -> tuple[object, object, object]:
        seeded = await store.seed_if_absent(seed)
        effective = await store.effective_policy(_scope())
        committed = await store.tighten(_scope(), overlay, seed.policy_digest)
        return seeded, effective, committed

    seeded, effective, committed = asyncio.run(run())

    assert seeded == seed
    assert effective.policy == seed and effective.generation == 1  # type: ignore[attr-defined]
    assert committed.policy == tightened and committed.generation == 2  # type: ignore[attr-defined]
    assert db.execute(
        "SELECT state FROM privacy_policy_versions ORDER BY policy_generation"
    ).fetchall() == [("superseded",), ("current",)]


@pytest.mark.parametrize("approved", [False, True])
def test_insert_only_repository_transition_load_commit_and_replay_are_exact(
    approved: bool,
) -> None:
    db = _database()
    store = CatalogPrivacyPolicyStore(db, _Clock())
    machine = _policy()
    repository_scope = AuthorizationScope(
        AuthorizationScopeKind.WORKSPACE, _INSTALLATION, _WORKSPACE
    )
    repository = replace(
        machine,
        policy_id="pvy_30000000-0000-4000-8000-000000000010",
        policy_digest=f"sha256:{'7' * 64}",
        effective_scope=repository_scope,
    )

    async def run() -> tuple[object, object, object]:
        await store.seed_if_absent(machine)
        authority = await store.repository_authority(repository_scope)
        proposal = PolicyTransitionProposal(
            repository_scope,
            authority.effective.generation,
            repository,
            canonical_digest({"candidate": repository.policy_digest}),
            _NOW,
            _NOW + timedelta(seconds=60),
            _PROPOSAL,
            authority.effective.effective_digest,
            authority.authority_digest,
            (PolicyTransitionMember("insert", repository_scope, repository, None, None),),
        )
        prepared = await store.prepare_transition(proposal)
        assert await store.prepare_transition(proposal) == prepared
        loaded = await store.load_pending_transition(_PROPOSAL)
        decision = HumanPolicyDecision(
            prepared.prepared_digest,
            approved,
            _NOW + timedelta(seconds=1),
            f"hmac-sha256:{'8' * 64}",
        )
        committed = await store.commit_transition(loaded, decision)
        restarted = CatalogPrivacyPolicyStore(db, _Clock())
        terminal = await restarted.load_transition(_PROPOSAL)
        replayed = await restarted.commit_transition(
            terminal,
            replace(decision, decided_at=decision.decided_at + timedelta(seconds=1)),
        )
        with pytest.raises(ValueError, match="privacy_policy_decision_mismatch"):
            await restarted.commit_transition(terminal, replace(decision, approved=not approved))
        return loaded, committed, replayed

    loaded, committed, replayed = asyncio.run(run())
    assert loaded.proposal.members[0].action == "insert"  # type: ignore[attr-defined]
    assert committed == replayed
    assert replayed.replayed is True  # type: ignore[attr-defined]
    assert committed.policy == (repository if approved else machine)  # type: ignore[attr-defined]
    transition = db.execute(
        "SELECT state, terminal_result_digest FROM privacy_policy_transitions"
    ).fetchone()
    assert transition is not None and transition[0] == ("committed" if approved else "denied")
    assert type(transition[1]) is str

    db.execute(
        "UPDATE privacy_policy_transitions SET terminal_result_canonical = ? WHERE proposal_id = ?",
        (b"{}", _PROPOSAL),
    )
    with pytest.raises(ValueError, match="privacy_policy_terminal_result_corrupt"):
        asyncio.run(
            CatalogPrivacyPolicyStore(db, _Clock()).commit_transition(
                asyncio.run(CatalogPrivacyPolicyStore(db, _Clock()).load_transition(_PROPOSAL)),
                HumanPolicyDecision(
                    loaded.prepared_digest,  # type: ignore[attr-defined]
                    approved,
                    _NOW + timedelta(seconds=3),
                    f"hmac-sha256:{'8' * 64}",
                ),
            )
        )


def test_v2_terminal_transition_migrates_to_stable_replay_identity() -> None:
    db = _database()
    store = CatalogPrivacyPolicyStore(db, _Clock())
    machine = _policy()
    repository_scope = AuthorizationScope(
        AuthorizationScopeKind.WORKSPACE, _INSTALLATION, _WORKSPACE
    )
    repository = replace(
        machine,
        policy_id="pvy_30000000-0000-4000-8000-000000000010",
        policy_digest=f"sha256:{'7' * 64}",
        effective_scope=repository_scope,
    )
    original_at = _NOW + timedelta(seconds=1)

    async def commit() -> HumanPolicyDecision:
        await store.seed_if_absent(machine)
        authority = await store.repository_authority(repository_scope)
        proposal = PolicyTransitionProposal(
            repository_scope,
            authority.effective.generation,
            repository,
            canonical_digest({"candidate": repository.policy_digest}),
            _NOW,
            _NOW + timedelta(seconds=60),
            _PROPOSAL,
            authority.effective.effective_digest,
            authority.authority_digest,
            (PolicyTransitionMember("insert", repository_scope, repository, None, None),),
        )
        prepared = await store.prepare_transition(proposal)
        decision = HumanPolicyDecision(
            prepared.prepared_digest,
            True,
            original_at,
            f"hmac-sha256:{'8' * 64}",
        )
        await store.commit_transition(prepared, decision)
        return decision

    decision = asyncio.run(commit())
    legacy_digest = canonical_digest(
        {
            "approved": True,
            "authority_commitment": decision.authority_commitment,
            "decided_at": format_rfc3339_millis(original_at),
            "prepared_digest": decision.prepared_digest,
        }
    )
    db.execute(
        "UPDATE privacy_policy_transitions SET decision_digest = ?, decision_at = NULL, "
        "terminal_result_version = NULL, terminal_at = ? WHERE proposal_id = ?",
        (legacy_digest, format_rfc3339_millis(original_at), _PROPOSAL),
    )

    async def replay() -> object:
        restarted = CatalogPrivacyPolicyStore(db, _Clock())
        loaded = await restarted.load_transition(_PROPOSAL)
        return await restarted.commit_transition(
            loaded, replace(decision, decided_at=original_at + timedelta(seconds=10))
        )

    replayed = asyncio.run(replay())
    assert replayed.replayed is True  # type: ignore[attr-defined]
    migrated = db.execute(
        "SELECT terminal_result_version, decision_at FROM privacy_policy_transitions "
        "WHERE proposal_id = ?",
        (_PROPOSAL,),
    ).fetchone()
    assert migrated == (1, format_rfc3339_millis(original_at))


def test_memory_and_sqlite_projection_replay_and_cursor_behavior_match() -> None:
    db = _database()
    unused_objects = cast(ObjectStorePort, _UnusedObjects())
    sqlite = CatalogPrivacyAudit(db, unused_objects, _Key(), _Clock())
    memory = MemoryPrivacyAudit(
        MemoryPrivacyCatalogState(),
        unused_objects,
        _Key(),
        _Clock(),  # type: ignore[arg-type]
    )
    second_request = _projection_request(_PROPOSAL_2, _REQUEST_2)
    second_receipt = replace(
        _receipt(),
        privacy_proposal_id=_PROPOSAL_2,
        request_id=_REQUEST_2,
        receipt_id=_RECEIPT_2,
    )

    async def run() -> tuple[tuple[str, ...], tuple[str, ...]]:
        for audit in (sqlite, memory):
            await audit.complete_agent_projection(_projection_request(), _receipt())
            replay = await audit.complete_agent_projection(_projection_request(), _receipt())
            assert replay.subject.projection_commitment.startswith("hmac-sha256:")
            contradiction = replace(
                _receipt(),
                counts=ReceiptCounts(0, 0, 0, 0, 0, 0, 3, 0, None),
            )
            with pytest.raises(ValueError, match="privacy_projection_replay_conflict"):
                await audit.complete_agent_projection(_projection_request(), contradiction)
            await audit.complete_agent_projection(second_request, second_receipt)
        sqlite_first = await sqlite.list_receipts(
            PrivacyReceiptQuery(limit=1), PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL
        )
        memory_first = await memory.list_receipts(
            PrivacyReceiptQuery(limit=1), PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL
        )
        assert sqlite_first.next_cursor is not None and memory_first.next_cursor is not None
        for audit, cursor in (
            (sqlite, sqlite_first.next_cursor),
            (memory, memory_first.next_cursor),
        ):
            tampered = cursor[:-1] + ("A" if cursor[-1] != "A" else "B")
            with pytest.raises(ValueError, match="privacy_receipt_cursor_invalid"):
                await audit.list_receipts(
                    PrivacyReceiptQuery(limit=1, cursor=tampered),
                    PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL,
                )
        sqlite_second = await sqlite.list_receipts(
            PrivacyReceiptQuery(limit=1, cursor=sqlite_first.next_cursor),
            PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL,
        )
        memory_second = await memory.list_receipts(
            PrivacyReceiptQuery(limit=1, cursor=memory_first.next_cursor),
            PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL,
        )
        assert tuple(
            view.receipt for view in sqlite_first.receipts + sqlite_second.receipts
        ) == tuple(view.receipt for view in memory_first.receipts + memory_second.receipts)
        return (
            tuple(
                view.receipt.receipt_id for view in sqlite_first.receipts + sqlite_second.receipts
            ),
            tuple(
                view.receipt.receipt_id for view in memory_first.receipts + memory_second.receipts
            ),
        )

    sqlite_ids, memory_ids = asyncio.run(run())

    assert sqlite_ids == memory_ids == (_RECEIPT_2, _RECEIPT)


def test_memory_and_sqlite_policy_generation_results_match() -> None:
    sqlite = CatalogPrivacyPolicyStore(_database(), _Clock())
    memory = MemoryPrivacyPolicyStore(MemoryPrivacyCatalogState(), _Clock())
    seed = _policy()

    async def run() -> tuple[tuple[int, PrivacyPolicy], tuple[int, PrivacyPolicy]]:
        await sqlite.seed_if_absent(seed)
        await memory.seed_if_absent(seed)
        sqlite_effective = await sqlite.effective_policy(_scope())
        memory_effective = await memory.effective_policy(_scope())
        return (
            (sqlite_effective.generation, sqlite_effective.policy),
            (memory_effective.generation, memory_effective.policy),
        )

    assert asyncio.run(run()) == ((1, seed), (1, seed))


def test_first_repository_carry_forward_provenance_is_exact_not_installation_wide() -> None:
    db = _database()
    store = CatalogPrivacyPolicyStore(db, _Clock())
    machine = minimal_external_policy()
    repository_a = AuthorizationScope(
        AuthorizationScopeKind.WORKSPACE, _INSTALLATION, "hmac-sha256:" + "1" * 64
    )
    repository_b = AuthorizationScope(
        AuthorizationScopeKind.WORKSPACE, _INSTALLATION, "hmac-sha256:" + "2" * 64
    )

    async def run() -> tuple[object, object, object]:
        await store.seed_if_absent(machine)
        available = await store.repository_authority(repository_a)
        carried = await store.carry_forward_repository_authority(repository_a)
        explicit = replace(
            machine,
            policy_id="pvy_30000000-0000-4000-8000-000000000011",
            policy_digest="sha256:" + "9" * 64,
            version=1,
            effective_scope=repository_b,
            supersedes_policy_digest=None,
        )
        await store.seed_if_absent(explicit)
        later = await store.repository_authority(repository_b)
        return available, carried, later

    available, carried, later = asyncio.run(run())
    assert available.migration_state == "first_repository_available"  # type: ignore[attr-defined]
    assert carried.migration_state == "consumed"  # type: ignore[attr-defined]
    assert later.grant_state == "granted"  # type: ignore[attr-defined]
    assert later.migration_state == "not_applicable"  # type: ignore[attr-defined]


def test_memory_and_sqlite_content_proposal_root_sets_match() -> None:
    db = _database()
    db.execute(
        """INSERT INTO task_routes (
               task_id, workspace_ref_commitment, external_ref_commitment,
               active_session_id, bundle_relpath, route_generation,
               active_route_identity_digest, state, quarantine_code, created_at, updated_at
           ) VALUES (?, NULL, NULL, ?, ?, 1, ?, 'active', NULL, ?, ?)""",
        (
            _TASK,
            _SESSION,
            f"tasks/{_TASK}",
            _ROUTE_DIGEST,
            _NOW.isoformat().replace("+00:00", "Z"),
            _NOW.isoformat().replace("+00:00", "Z"),
        ),
    )
    memory_state = MemoryPrivacyCatalogState(routes={_TASK: _ROUTE_DIGEST})
    sqlite = CatalogPrivacyAudit(db, _Objects(), _Key(), _Clock())  # type: ignore[arg-type]
    memory = MemoryPrivacyAudit(memory_state, _Objects(), _Key(), _Clock())  # type: ignore[arg-type]
    prepared = canonical_encode({"items": []})
    minimized = MinimizedDisclosure(
        prepared,
        (),
        (),
        (),
        (),
        (("removed_items", 0),),
        len(prepared),
        0,
        canonical_digest({"items": []}),
        "scanner-v1",
        _DIGEST,
        (),
    )
    request = DisclosureProposalRequest(
        _PROPOSAL,
        _REQUEST,
        _TASK,
        minimized,
        None,
        LocalDisclosureSink.TRUSTED_HUMAN_CONTROL,
        "trusted-preview",
        _task_scope(),
        _POLICY,
        1,
        1,
        _DIGEST,
        len(prepared),
        0,
        _NOW + timedelta(minutes=1),
    )

    async def run() -> tuple[tuple[object, ...], tuple[object, ...]]:
        results: list[tuple[object, ...]] = []
        for audit in (sqlite, memory):
            reserved = await audit.prepare_disclosure_proposal(request)
            assert reserved.proposal.scanner_registry_version == minimized.scanner_registry_version
            assert reserved.proposal.scanner_profile_digest == minimized.scanner_profile_digest
            roots = await audit.live_object_roots(_TASK, _ROUTE_DIGEST)
            results.append(
                (
                    reserved.proposal.proposal_commitment,
                    roots.privacy_root_generation,
                    roots.root_set_digest,
                    tuple(ref.object_id for ref in roots.object_refs),
                )
            )
        return results[0], results[1]

    sqlite_result, memory_result = asyncio.run(run())

    assert sqlite_result == memory_result
    assert sqlite_result[3] == (_OBJECT,)


def test_minimized_disclosure_rejects_an_oversized_opaque_omission_set() -> None:
    minimized = _external_disclosure_request().minimized
    too_many = tuple(f"item-{index:03d}" for index in range(MAX_WITHHELD_ITEM_IDS + 1))

    with pytest.raises(ValueError, match="invalid_privacy_port_value"):
        replace(minimized, withheld_item_ids=too_many)


def test_memory_and_sqlite_agree_on_which_disclosures_are_still_decidable() -> None:
    """Both audit implementations list the same waiting proposals, and exclude expired ones.

    An expired proposal is refused by the decision path, so listing it would advertise a
    ceremony that cannot succeed -- the opposite of what a caller reaching for this needs.
    """

    db = _database()
    db.execute(
        """INSERT INTO task_routes (
               task_id, workspace_ref_commitment, external_ref_commitment,
               active_session_id, bundle_relpath, route_generation,
               active_route_identity_digest, state, quarantine_code, created_at, updated_at
           ) VALUES (?, NULL, NULL, ?, ?, 1, ?, 'active', NULL, ?, ?)""",
        (
            _TASK,
            _SESSION,
            f"tasks/{_TASK}",
            _ROUTE_DIGEST,
            _NOW.isoformat().replace("+00:00", "Z"),
            _NOW.isoformat().replace("+00:00", "Z"),
        ),
    )
    memory_state = MemoryPrivacyCatalogState(routes={_TASK: _ROUTE_DIGEST})
    sqlite = CatalogPrivacyAudit(db, _Objects(), _Key(), _Clock())  # type: ignore[arg-type]
    memory = MemoryPrivacyAudit(memory_state, _Objects(), _Key(), _Clock())  # type: ignore[arg-type]
    prepared = canonical_encode({"items": []})
    minimized = MinimizedDisclosure(
        prepared,
        (),
        (),
        (),
        (),
        (("removed_items", 0),),
        len(prepared),
        0,
        canonical_digest({"items": []}),
        "scanner-v1",
        _DIGEST,
        (),
    )
    live = DisclosureProposalRequest(
        _PROPOSAL,
        _REQUEST,
        _TASK,
        minimized,
        None,
        LocalDisclosureSink.TRUSTED_HUMAN_CONTROL,
        "trusted-preview",
        _task_scope(),
        _POLICY,
        1,
        1,
        _DIGEST,
        len(prepared),
        0,
        _NOW + timedelta(minutes=1),
    )

    # `_Clock` is fixed at _NOW. A second pair reading five minutes later sees the same stored
    # proposal past its one-minute expiry, so the clock is the only difference between the two
    # observations.
    class _LateClock:
        def now_utc(self) -> datetime:
            return _NOW + timedelta(minutes=5)

    late = (
        CatalogPrivacyAudit(db, _Objects(), _Key(), _LateClock()),  # type: ignore[arg-type]
        MemoryPrivacyAudit(memory_state, _Objects(), _Key(), _LateClock()),  # type: ignore[arg-type]
    )

    async def listed(audit: object) -> tuple[str, ...]:
        page = await cast(CatalogPrivacyAudit, audit).list_pending_disclosures(
            PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL
        )
        return tuple(entry.pending_id for entry in page.pending)

    async def run() -> tuple[tuple[str, ...], ...]:
        for audit in (sqlite, memory):
            await audit.prepare_disclosure_proposal(live)
        return (
            await listed(sqlite),
            await listed(memory),
            await listed(late[0]),
            await listed(late[1]),
        )

    sqlite_now, memory_now, sqlite_late, memory_late = asyncio.run(run())

    assert sqlite_now == memory_now == (_PROPOSAL,)
    assert sqlite_late == memory_late == ()


def test_coordinator_empty_client_projection_completes_one_durable_receipt() -> None:
    state = MemoryPrivacyCatalogState()
    policies = MemoryPrivacyPolicyStore(state, _Clock())
    audit = MemoryPrivacyAudit(
        state,
        cast(ObjectStorePort, _UnusedObjects()),
        _Key(),
        _Clock(),  # type: ignore[arg-type]
    )
    coordinator = PrivacyCoordinator(
        policies,
        LocalPrivacyEnforcer(),
        audit,
        _Gateway(),  # type: ignore[arg-type]
        _Clock(),
        _Ids(),
    )
    empty = canonical_encode({})
    candidate = CandidateContext(
        _REQUEST,
        None,
        LocalDisclosureSink.AGENT_CONTEXT,
        "client_result_projection",
        _scope(),
        _DIGEST,
        None,
        (),
        None,
        ProjectionAuditContext(
            _RPC,
            "check",
            _SERVICE,
            1,
            None,
            None,
            empty,
            empty,
        ),
    )

    async def run() -> object:
        await policies.seed_if_absent(_policy())
        return await coordinator.prepare_local_disclosure(candidate)

    result = asyncio.run(run())

    assert type(result) is LocalDisclosureApproved
    assert result.approved_items == ()
    assert result.omissions == ()
    assert result.receipt.outcome is PrivacyOutcome.COMPLETED
    assert len(state.audit) == 1


def test_catalog_resume_finds_disclosure_by_case_digest() -> None:
    """AI-powered review resume must translate the public case digest to the private audit identity."""

    db = _database()
    _insert_task_route(db)
    objects = _StoredObjects()
    audit = CatalogPrivacyAudit(db, objects, _Key(), _Clock())  # type: ignore[arg-type]
    coordinator = PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, object()),
        cast(PrivacyClassifierPort, object()),
        audit,
        cast(OutboundGatewayPort, _Gateway()),
        _Clock(),
        _Ids(),
    )

    async def run() -> object:
        await audit.prepare_disclosure_proposal(_external_disclosure_request())
        return await coordinator.resume(
            _REQUEST,
            _DIGEST,
            Deadline(_NOW + timedelta(minutes=5), 301.0),
        )

    result = asyncio.run(run())

    assert isinstance(result, SemanticEgressAwaitingHuman)
    assert result.request_id == _REQUEST
    assert result.privacy_proposal_id == _PROPOSAL


def test_catalog_resume_rejects_replaced_active_route() -> None:
    db = _database()
    _insert_task_route(db)
    objects = _StoredObjects()
    audit = CatalogPrivacyAudit(db, objects, _Key(), _Clock())  # type: ignore[arg-type]

    async def run() -> None:
        prepared = await audit.prepare_disclosure_proposal(_external_disclosure_request())
        assert prepared.proposal.route_identity_digest == _ROUTE_DIGEST
        assert prepared.proposal.included_item_ids == ("item-1",)
        db.execute(
            "UPDATE task_routes SET active_route_identity_digest = ? WHERE task_id = ?",
            (f"sha256:{'9' * 64}", _TASK),
        )
        assert await audit.load_disclosure_proposal(prepared.proposal.privacy_proposal_id) is None

    asyncio.run(run())


def test_catalog_proposal_persists_redacted_value_lines_for_resume() -> None:
    """PL2-1 (issue #982): refs and lines survive the proposal round trip; absent stays absent."""

    from finishup.protocol.redacted_values import SemanticRedactedValue

    db = _database()
    _insert_task_route(db)
    objects = _StoredObjects()
    audit = CatalogPrivacyAudit(db, objects, _Key(), _Clock())  # type: ignore[arg-type]
    values = (SemanticRedactedValue("item-1", "value_replaced", (2, 5), "evd_ref-1"),)

    async def run() -> None:
        request = _external_disclosure_request()
        prepared = await audit.prepare_disclosure_proposal(
            replace(request, minimized=replace(request.minimized, redacted_values=values))
        )
        assert prepared.proposal.redacted_values == values
        loaded = await audit.load_disclosure_proposal(prepared.proposal.privacy_proposal_id)
        assert loaded is not None
        assert loaded.redacted_values == values

    asyncio.run(run())


def test_catalog_disclosure_attempt_rejects_tampered_lookup_identity() -> None:
    db = _database()
    _insert_task_route(db)
    objects = _StoredObjects()
    audit = CatalogPrivacyAudit(db, objects, _Key(), _Clock())  # type: ignore[arg-type]

    async def run() -> None:
        prepared = await audit.prepare_disclosure_proposal(_external_disclosure_request())
        db.execute(
            "UPDATE privacy_audit_records SET subject_lookup_identity = ? WHERE proposal_id = ?",
            (f"hmac-sha256:{'9' * 64}", prepared.proposal.privacy_proposal_id),
        )
        with pytest.raises(ValueError, match="privacy_audit_attempt_corrupt"):
            await audit.load_disclosure_attempt(
                prepared.proposal.request_id,
                prepared.proposal.prepared_case_digest,
            )

    asyncio.run(run())


@pytest.fixture(params=("memory", "catalog"))
def disclosure_audit(request: pytest.FixtureRequest) -> PrivacyAuditPort:
    if request.param == "memory":
        return MemoryPrivacyAudit(
            MemoryPrivacyCatalogState(routes={_TASK: _ROUTE_DIGEST}),
            cast(ObjectStorePort, _StoredObjects()),
            _Key(),
            _Clock(),
        )  # type: ignore[arg-type]
    db = _database()
    _insert_task_route(db)
    return CatalogPrivacyAudit(db, _StoredObjects(), _Key(), _Clock())  # type: ignore[arg-type]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("request_id", "digest", "error"),
    (
        (None, _DIGEST, TypeError),
        (_REQUEST, None, TypeError),
        (True, _DIGEST, TypeError),
        (_REQUEST, b"digest", TypeError),
        ("req_invalid", _DIGEST, ValueError),
        (_REQUEST.upper(), _DIGEST, ValueError),
        (_REQUEST, "sha256:bad", ValueError),
        (_REQUEST, "sha256:" + "A" * 64, ValueError),
    ),
)
async def test_disclosure_lookup_input_contract_matches_across_adapters(
    disclosure_audit: PrivacyAuditPort,
    request_id: object,
    digest: object,
    error: type[Exception],
) -> None:
    with pytest.raises(error, match="privacy_disclosure_attempt_lookup_invalid"):
        await disclosure_audit.load_disclosure_attempt(cast(str, request_id), cast(str, digest))


@pytest.mark.anyio
async def test_disclosure_lookup_distinguishes_absence_match_and_mismatch(
    disclosure_audit: PrivacyAuditPort,
) -> None:
    assert await disclosure_audit.load_disclosure_attempt(_REQUEST, _DIGEST) is None
    prepared = await disclosure_audit.prepare_disclosure_proposal(_external_disclosure_request())
    state = await disclosure_audit.load_disclosure_attempt(_REQUEST, _DIGEST)
    assert state is not None and state.reservation == prepared.reservation
    assert await disclosure_audit.load_disclosure_attempt(_REQUEST_2, _DIGEST) is None
    with pytest.raises(ValueError, match="privacy_audit_attempt_case_mismatch"):
        await disclosure_audit.load_disclosure_attempt(_REQUEST, "sha256:" + "4" * 64)


@pytest.mark.anyio
@pytest.mark.parametrize("mutation", ("absent", "null", "number", "malformed"))
async def test_authenticated_disclosure_sidecar_requires_a_valid_case_digest(mutation: str) -> None:
    db = _database()
    _insert_task_route(db)
    audit = CatalogPrivacyAudit(db, _StoredObjects(), _Key(), _Clock())  # type: ignore[arg-type]
    await audit.prepare_disclosure_proposal(_external_disclosure_request())
    row = db.execute("SELECT subject_structural_canonical FROM privacy_audit_records").fetchone()
    assert row is not None and isinstance(row[0], bytes)
    structural = json.loads(row[0])
    if mutation == "absent":
        del structural["prepared_case_digest"]
    else:
        structural["prepared_case_digest"] = {"null": None, "number": 3, "malformed": "bad"}[
            mutation
        ]
    raw = canonical_encode(structural)
    # Authenticate the synthetic malformed sidecar, so the test reaches structural
    # validation rather than passing merely because its MAC is invalid.
    identity = _mac(_Key(), _LOOKUP_DOMAIN, raw)
    db.execute(
        "UPDATE privacy_audit_records SET subject_structural_canonical = ?, subject_lookup_identity = ?",
        (raw, identity),
    )
    with pytest.raises(ValueError, match="privacy_audit_attempt_corrupt"):
        await audit.load_disclosure_attempt(_REQUEST, _DIGEST)


@pytest.mark.anyio
async def test_disclosure_lookup_storage_failure_is_not_absence() -> None:
    db = _database()
    audit = CatalogPrivacyAudit(db, _StoredObjects(), _Key(), _Clock())  # type: ignore[arg-type]
    db.close()
    with pytest.raises(apsw.ConnectionClosedError):
        await audit.load_disclosure_attempt(_REQUEST, _DIGEST)


def test_catalog_disclosure_attempt_rejects_multiple_rows_for_request() -> None:
    db = _database()
    _insert_task_route(db)
    objects = _StoredObjects((_OBJECT, _OBJECT_2))
    audit = CatalogPrivacyAudit(db, objects, _Key(), _Clock())  # type: ignore[arg-type]

    async def run() -> None:
        request = _external_disclosure_request()
        await audit.prepare_disclosure_proposal(request)
        await audit.prepare_disclosure_proposal(replace(request, privacy_proposal_id=_PROPOSAL_2))
        with pytest.raises(ValueError, match="privacy_audit_attempt_ambiguous"):
            await audit.load_disclosure_attempt(_REQUEST, _DIGEST)

    asyncio.run(run())


def test_catalog_consumed_disclosure_attempt_is_durable_and_one_use() -> None:
    """A consumed authorization remains receipt-pending and cannot be consumed twice."""

    db = _database()
    _insert_task_route(db)
    audit = CatalogPrivacyAudit(db, _StoredObjects(), _Key(), _Clock())  # type: ignore[arg-type]

    async def run() -> tuple[
        EgressAuthorization,
        ConsumedAuthorization,
        PrivacyAuditState | None,
        PrivacyAuditState | None,
        SemanticEgressAttemptUnknown,
    ]:
        prepared = await audit.prepare_disclosure_proposal(_external_disclosure_request())
        authorization = await audit.authorize(
            prepared.proposal.privacy_proposal_id,
            prepared.proposal.prepared_case_digest,
            _NOW,
        )
        consumed = await audit.consume(authorization.authorization_id, _DISPATCH, _NOW)
        state = await audit.load(
            prepared.proposal.request_id,
            prepared.reservation.subject_digest,
        )
        attempt_state = await audit.load_disclosure_attempt(
            prepared.proposal.request_id,
            prepared.proposal.prepared_case_digest,
        )
        with pytest.raises(ValueError, match="privacy_audit_attempt_case_mismatch"):
            await audit.load_disclosure_attempt(
                prepared.proposal.request_id,
                f"sha256:{'4' * 64}",
            )
        with pytest.raises(ValueError, match="privacy_audit_authorization_unavailable"):
            await audit.consume(authorization.authorization_id, _DISPATCH, _NOW)
        coordinator = PrivacyCoordinator(
            cast(PrivacyPolicyStorePort, object()),
            cast(PrivacyClassifierPort, object()),
            audit,
            cast(OutboundGatewayPort, _Gateway()),
            _Clock(),
            _Ids(),
        )
        recovered = await coordinator.recover_started_attempt(
            prepared.proposal.request_id,
            prepared.proposal.prepared_case_digest,
            Deadline(_NOW + timedelta(minutes=5), 301.0),
        )
        assert isinstance(recovered, SemanticEgressAttemptUnknown)
        return authorization, consumed, state, attempt_state, recovered

    authorization, consumed, state, attempt_state, recovered = asyncio.run(run())

    assert authorization.authorization_id
    assert consumed.dispatch_id == _DISPATCH  # type: ignore[attr-defined]
    assert state is not None
    assert state.status == "receipt_pending"
    assert state.authorization_id == authorization.authorization_id
    assert state.dispatch_id == _DISPATCH
    assert state.receipt_id is None
    assert attempt_state == state
    assert recovered.request_id == _REQUEST
    assert recovered.privacy_proposal_id == _PROPOSAL
    assert asyncio.run(audit.load(_REQUEST, _DIGEST)) is None


def _unknown_attempt_receipt(authorization: EgressAuthorization) -> EgressReceipt:
    """The ``outcome_unknown`` receipt an admitted physical attempt owes when its result is lost."""

    return EgressReceipt(
        "1.0.0",
        _RECEIPT,
        _REQUEST,
        authorization.privacy_proposal_id,
        EgressChannel.LLM_INFERENCE,
        PrivacyOutcome.TRANSPORT_FAILED,
        _NOW,
        authorization.scope,
        authorization.purpose,
        authorization.provider_binding,
        ReceiptPolicyBinding(_POLICY, authorization.policy_version, _DIGEST, _DIGEST),
        authorization.consent_source,
        (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        (),
        ReceiptCounts(1, 1, 0, 1, 0, 32, 32, 8, 96),
        ReceiptTransformations(0, 0, 0),
        ReceiptSecretScan("scanner-v1", _DIGEST, 0, True),
        PrivacyReason.OUTCOME_UNKNOWN,
        1,
        authorization_id=authorization.authorization_id,
        dispatch_id=_DISPATCH,
        dispatch_started_at=_NOW - timedelta(seconds=5),
        request_commitment=RequestCommitment(
            "hmac-sha256/yoetz-privacy-egress-request-v1", _WORKSPACE
        ),
    )


def _advice_repository() -> tuple[apsw.Connection, SqliteObservationAdviceSemanticRepository, str]:
    advice_db = apsw.Connection(":memory:")
    initialize_bundle(advice_db, {"task_id": _TASK, "owner_generation": "1"})
    repository = SqliteObservationAdviceSemanticRepository(advice_db)
    basis = f"sha256:{'9' * 64}"
    repository.schedule(
        workspace=_WORKSPACE,
        yoetz_session_id=_SESSION,
        basis_digest=basis,
        subject_digest=basis,
        coverage_gaps=(),
        packet_json=b"{}",
        enqueued_at=format_rfc3339_millis(_NOW),
        max_pending=16,
    )
    return advice_db, repository, basis


def _coordinator(audit: CatalogPrivacyAudit) -> PrivacyCoordinator:
    return PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, object()),
        cast(PrivacyClassifierPort, object()),
        audit,
        cast(OutboundGatewayPort, _Gateway()),
        _Clock(),
        _Ids(),
    )


def _audit_row_state(db: apsw.Connection) -> tuple[object, ...]:
    row = db.execute(
        "SELECT state, receipt_outcome, receipt_reason, receipt_id FROM privacy_audit_records"
    ).fetchone()
    assert row is not None
    return tuple(row)


def test_cancelled_advice_attempt_reconciles_consumed_egress_to_unknown() -> None:
    """Foreground preemption owes the consumed attempt exactly one terminal receipt (#755).

    The cancelled advice row is never a semantic success, and it is not proof that no physical
    provider call started. When the privacy audit consumed the disclosure authorization before
    the yield landed, the gateway parks the owed ``outcome_unknown`` receipt, the worker records
    that provenance on the cancelled row, and the reconciliation stays idempotent: the provider
    is never re-entered.
    """

    catalog_db = _database()
    _insert_task_route(catalog_db)
    audit = CatalogPrivacyAudit(catalog_db, _StoredObjects(), _Key(), _Clock())  # type: ignore[arg-type]
    advice_db, repository, basis = _advice_repository()
    coordinator = _coordinator(audit)
    prepared_case_digest: list[str] = []
    dispatch_calls = 0

    async def dispatch(
        _attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome:
        nonlocal dispatch_calls
        dispatch_calls += 1
        prepared = await audit.prepare_disclosure_proposal(_external_disclosure_request())
        prepared_case_digest.append(prepared.proposal.prepared_case_digest)
        authorization = await audit.authorize(
            prepared.proposal.privacy_proposal_id,
            prepared.proposal.prepared_case_digest,
            _NOW,
        )
        # The gateway stores the receipt it owes in the consume transaction, before the provider
        # call; cancellation lands in that admitted window.
        await audit.consume(
            authorization.authorization_id,
            _DISPATCH,
            _NOW,
            owed_receipt=_unknown_attempt_receipt(authorization),
        )
        raise asyncio.CancelledError

    async def reconcile(
        _attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome | None:
        recovered = await coordinator.recover_started_request(_REQUEST)
        if recovered is None:
            return None
        return ObservationAdviceSemanticOutcome(
            status="cancelled",
            failure_reason="cancelled",
            attempt_receipt=recovered.receipt_id or recovered.privacy_proposal_id,
            provider_identity="provider-under-test",
        )

    worker = ObservationAdviceSemanticWorker(
        repository=repository,
        dispatch=dispatch,
        service_generation=1,
        lease_owner="svc-advice",
        now=lambda: format_rfc3339_millis(_NOW),
        lease_expires_at=lambda: format_rfc3339_millis(_NOW + timedelta(minutes=2)),
        reconcile_cancelled=reconcile,
    )
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(worker.run_once())

    row = repository.lookup(yoetz_session_id=_SESSION, basis_digest=basis)
    assert row is not None
    assert (row.status, row.failure_reason) == ("cancelled", "cancelled")
    # Cancellation provenance: this row names the consumed egress reservation it reconciled and
    # the provider whose outcome is unknown, so the coverage gap is not silently anonymous.
    assert (row.attempt_receipt, row.provider_identity) == (_PROPOSAL, "provider-under-test")
    assert dispatch_calls == 1
    assert len(prepared_case_digest) == 1

    # Before the reconciliation sweep the consumed authorization is nonterminal but recoverable.
    assert _audit_row_state(catalog_db) == ("receipt_pending", None, None, None)
    recovered = asyncio.run(
        coordinator.recover_started_attempt(
            _REQUEST,
            prepared_case_digest[0],
            Deadline(_NOW + timedelta(minutes=5), 301.0),
        )
    )
    assert isinstance(recovered, SemanticEgressAttemptUnknown)
    assert recovered.privacy_proposal_id == _PROPOSAL

    # The bounded startup sweep terminalizes it as transport_failed/outcome_unknown, exactly once.
    reconciled = asyncio.run(coordinator.reconcile_started_attempts(_NOW + timedelta(minutes=1)))
    assert reconciled == 1
    assert _audit_row_state(catalog_db) == (
        "attempt_completed",
        "transport_failed",
        "outcome_unknown",
        _RECEIPT,
    )
    assert asyncio.run(coordinator.reconcile_started_attempts(_NOW + timedelta(minutes=1))) == 0
    again = asyncio.run(
        coordinator.recover_started_attempt(
            _REQUEST,
            prepared_case_digest[0],
            Deadline(_NOW + timedelta(minutes=5), 301.0),
        )
    )
    assert isinstance(again, SemanticEgressAttemptUnknown)
    assert again.receipt_id == _RECEIPT
    assert dispatch_calls == 1
    advice_db.close()


def test_startup_reconciliation_closes_a_receipt_pending_row_left_by_a_restart() -> None:
    """No parked attempt may stay ``receipt_pending`` past a service restart (#755).

    The sweep is bounded by the current service start: an attempt consumed after that instant is
    still live and must never be closed, while one consumed before it is reconciled exactly once
    with no second provider dispatch.
    """

    db = _database()
    _insert_task_route(db)
    audit = CatalogPrivacyAudit(db, _StoredObjects(), _Key(), _Clock())  # type: ignore[arg-type]
    coordinator = _coordinator(audit)

    async def seed() -> None:
        prepared = await audit.prepare_disclosure_proposal(_external_disclosure_request())
        authorization = await audit.authorize(
            prepared.proposal.privacy_proposal_id,
            prepared.proposal.prepared_case_digest,
            _NOW,
        )
        await audit.consume(
            authorization.authorization_id,
            _DISPATCH,
            _NOW,
            owed_receipt=_unknown_attempt_receipt(authorization),
        )

    asyncio.run(seed())
    assert _audit_row_state(db) == ("receipt_pending", None, None, None)

    # A sweep whose boundary predates the consume leaves the live attempt alone.
    assert asyncio.run(coordinator.reconcile_started_attempts(_NOW - timedelta(minutes=1))) == 0
    assert _audit_row_state(db) == ("receipt_pending", None, None, None)

    # A restart sweep terminalizes it, and a second pass is a no-op.
    assert asyncio.run(coordinator.reconcile_started_attempts(_NOW + timedelta(minutes=1))) == 1
    assert asyncio.run(coordinator.reconcile_started_attempts(_NOW + timedelta(minutes=1))) == 0
    assert _audit_row_state(db) == (
        "attempt_completed",
        "transport_failed",
        "outcome_unknown",
        _RECEIPT,
    )
    view = asyncio.run(audit.get_receipt(_RECEIPT, PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL))
    assert view is not None
    assert view.receipt.outcome is PrivacyOutcome.TRANSPORT_FAILED
    assert view.receipt.safe_failure_reason is PrivacyReason.OUTCOME_UNKNOWN


def test_consume_parks_the_owed_receipt_in_the_same_transaction() -> None:
    """#1118 unit 1: a crash right after consume still leaves the owed receipt to reconcile.

    No separate parking write follows the consume, so there is no window in which the
    authorization is spent but its ``outcome_unknown`` receipt is missing.
    """

    db = _database()
    _insert_task_route(db)
    audit = CatalogPrivacyAudit(db, _StoredObjects(), _Key(), _Clock())  # type: ignore[arg-type]
    coordinator = _coordinator(audit)

    async def consume_then_crash() -> None:
        prepared = await audit.prepare_disclosure_proposal(_external_disclosure_request())
        authorization = await audit.authorize(
            prepared.proposal.privacy_proposal_id,
            prepared.proposal.prepared_case_digest,
            _NOW,
        )
        await audit.consume(
            authorization.authorization_id,
            _DISPATCH,
            _NOW,
            owed_receipt=_unknown_attempt_receipt(authorization),
        )

    asyncio.run(consume_then_crash())
    assert _audit_row_state(db) == ("receipt_pending", None, None, None)
    assert asyncio.run(coordinator.reconcile_started_attempts(_NOW + timedelta(minutes=1))) == 1
    assert _audit_row_state(db) == (
        "attempt_completed",
        "transport_failed",
        "outcome_unknown",
        _RECEIPT,
    )


def test_advice_cancellation_before_consume_leaves_authority_unspent() -> None:
    """Cancelling before the consume CAS spends nothing and invents no reconciliation (#755)."""

    catalog_db = _database()
    _insert_task_route(catalog_db)
    audit = CatalogPrivacyAudit(catalog_db, _StoredObjects(), _Key(), _Clock())  # type: ignore[arg-type]
    advice_db, repository, basis = _advice_repository()
    coordinator = _coordinator(audit)
    reconcile_calls = 0

    async def dispatch(
        _attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome:
        prepared = await audit.prepare_disclosure_proposal(_external_disclosure_request())
        await audit.authorize(
            prepared.proposal.privacy_proposal_id,
            prepared.proposal.prepared_case_digest,
            _NOW,
        )
        raise asyncio.CancelledError

    async def reconcile(
        _attempt: ObservationAdviceSemanticAttempt,
    ) -> ObservationAdviceSemanticOutcome | None:
        nonlocal reconcile_calls
        reconcile_calls += 1
        recovered = await coordinator.recover_started_request(_REQUEST)
        if recovered is None:
            return None
        raise AssertionError("an unconsumed authorization must not report a started attempt")

    worker = ObservationAdviceSemanticWorker(
        repository=repository,
        dispatch=dispatch,
        service_generation=1,
        lease_owner="svc-advice",
        now=lambda: format_rfc3339_millis(_NOW),
        lease_expires_at=lambda: format_rfc3339_millis(_NOW + timedelta(minutes=2)),
        reconcile_cancelled=reconcile,
    )
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(worker.run_once())

    row = repository.lookup(yoetz_session_id=_SESSION, basis_digest=basis)
    assert row is not None
    assert (row.status, row.failure_reason) == ("cancelled", "cancelled")
    assert (row.attempt_receipt, row.provider_identity) == (None, None)
    assert reconcile_calls == 1
    assert _audit_row_state(catalog_db) == ("authorized", None, None, None)
    assert asyncio.run(coordinator.reconcile_started_attempts(_NOW + timedelta(minutes=1))) == 0
    advice_db.close()


def test_unreadable_audit_keeps_the_cancelled_call_usage_unknown() -> None:
    """An audit that cannot be read never proves a minted request sent nothing (#923).

    ``recover_started_request`` must not collapse an unreadable lookup into ``None`` (the proof
    that authority was never consumed): the cancelled advice row then keeps its provider marker.
    """

    from finishup.application.observation_advice_semantic import (
        reconcile_cancelled_advice_request,
    )

    class _UnreadableAudit(CatalogPrivacyAudit):
        async def load_started_disclosure_attempt(self, request_id: str) -> None:
            raise apsw.IOError("disk I/O error")

    catalog_db = _database()
    audit = _UnreadableAudit(catalog_db, _StoredObjects(), _Key(), _Clock())  # type: ignore[arg-type]
    coordinator = _coordinator(audit)

    with pytest.raises(apsw.IOError):
        asyncio.run(coordinator.recover_started_request(_REQUEST))
    outcome = asyncio.run(
        reconcile_cancelled_advice_request(
            (_REQUEST, "provider-under-test"), coordinator.recover_started_request
        )
    )
    assert outcome == ObservationAdviceSemanticOutcome(
        status="cancelled", failure_reason="cancelled", provider_identity="provider-under-test"
    )


def _network_receipt(authorization: EgressAuthorization) -> EgressReceipt:
    """The receipt a completed subscription review records through the gateway."""

    return EgressReceipt(
        "1.0.0",
        _RECEIPT,
        authorization_request_id(authorization),
        authorization.privacy_proposal_id,
        EgressChannel.LLM_INFERENCE,
        PrivacyOutcome.COMPLETED,
        _NOW,
        authorization.scope,
        authorization.purpose,
        authorization.provider_binding,
        ReceiptPolicyBinding(_POLICY, authorization.policy_version, _DIGEST, _DIGEST),
        authorization.consent_source,
        (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        (),
        ReceiptCounts(1, 1, 0, 1, 0, 32, 32, 8, 96),
        ReceiptTransformations(0, 0, 0),
        ReceiptSecretScan("scanner-v1", _DIGEST, 0, True),
        None,
        1,
        authorization_id=authorization.authorization_id,
        dispatch_id=_DISPATCH,
        dispatch_started_at=_NOW - timedelta(seconds=5),
        request_commitment=RequestCommitment(
            "hmac-sha256/yoetz-privacy-egress-request-v1", _WORKSPACE
        ),
    )


def authorization_request_id(authorization: EgressAuthorization) -> str:
    del authorization
    return _REQUEST


def test_completed_network_egress_receipt_is_retrievable_and_listable() -> None:
    """A stored network receipt reads back whole; it used to raise a deferred-codec error.

    Issue #730: the only receipts a real AI-powered review records are network egress receipts,
    and ``get_receipt`` refused every one of them while ``list_receipts`` silently dropped them.
    """

    db = _database()
    _insert_task_route(db)
    audit = CatalogPrivacyAudit(db, _StoredObjects(), _Key(), _Clock())  # type: ignore[arg-type]

    async def run() -> tuple[
        EgressReceipt, PrivacyReceiptView | None, PrivacyReceiptPage, PrivacyReceiptPage
    ]:
        prepared = await audit.prepare_disclosure_proposal(_external_disclosure_request())
        authorization = await audit.authorize(
            prepared.proposal.privacy_proposal_id,
            prepared.proposal.prepared_case_digest,
            _NOW,
        )
        await audit.consume(authorization.authorization_id, _DISPATCH, _NOW)
        receipt = _network_receipt(authorization)
        await audit.complete_egress(_DISPATCH, receipt)
        fetched = await audit.get_receipt(_RECEIPT, PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL)
        by_provider = await audit.list_receipts(
            PrivacyReceiptQuery(
                channel=EgressChannel.LLM_INFERENCE,
                provider_id="provider-test",
                endpoint_profile_id="endpoint-test",
                outcome=PrivacyOutcome.COMPLETED,
            ),
            PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL,
        )
        other_provider = await audit.list_receipts(
            PrivacyReceiptQuery(provider_id="someone-else"),
            PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL,
        )
        return receipt, fetched, by_provider, other_provider

    receipt, fetched, by_provider, other_provider = asyncio.run(run())

    expected = cast(EgressReceipt, _legacy_receipt_view(receipt))
    assert fetched == NetworkEgressReceiptView("network_egress", expected)
    assert by_provider.receipts == (fetched,)
    assert other_provider.receipts == ()


def test_stored_receipts_of_both_kinds_list_together_newest_first() -> None:
    db = _database()
    _insert_task_route(db)
    audit = CatalogPrivacyAudit(db, _StoredObjects(), _Key(), _Clock())  # type: ignore[arg-type]
    local = replace(
        _receipt(),
        privacy_proposal_id=_PROPOSAL_2,
        request_id=_REQUEST_2,
        receipt_id=_RECEIPT_2,
        finished_at=_NOW - timedelta(minutes=1),
    )

    async def run() -> PrivacyReceiptPage:
        prepared = await audit.prepare_disclosure_proposal(_external_disclosure_request())
        authorization = await audit.authorize(
            prepared.proposal.privacy_proposal_id,
            prepared.proposal.prepared_case_digest,
            _NOW,
        )
        await audit.consume(authorization.authorization_id, _DISPATCH, _NOW)
        await audit.complete_egress(_DISPATCH, _network_receipt(authorization))
        await audit.complete_agent_projection(_projection_request(_PROPOSAL_2, _REQUEST_2), local)
        return await audit.list_receipts(
            PrivacyReceiptQuery(), PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL
        )

    page = asyncio.run(run())

    assert [type(view) for view in page.receipts] == [
        NetworkEgressReceiptView,
        LocalDisclosureReceiptView,
    ]
    assert [view.receipt.receipt_id for view in page.receipts] == [_RECEIPT, _RECEIPT_2]


def _stored_projection(audit: CatalogPrivacyAudit, index: int) -> LocalDisclosureReceipt:
    receipt = replace(
        _receipt(),
        receipt_id=f"egr_30000000-0000-4000-8000-{index:012d}",
        request_id=f"req_30000000-0000-4000-8000-{index:012d}",
        privacy_proposal_id=f"ppr_30000000-0000-4000-8000-{index:012d}",
        finished_at=_NOW - timedelta(seconds=index),
    )
    request = _projection_request(receipt.privacy_proposal_id, receipt.request_id)
    asyncio.run(audit.complete_agent_projection(request, receipt))
    return receipt


def test_an_unreadable_row_is_skipped_counted_and_named_not_fatal_to_the_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #921: one stored row that cannot be read back used to fail every receipt beside it."""

    import finishup.observability.diagnostics as diagnostics_module

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    db = _database()
    audit = CatalogPrivacyAudit(db, _UnusedObjects(), _Key(), _Clock())  # type: ignore[arg-type]
    stored = [_stored_projection(audit, index) for index in range(1, 7)]
    garbled, older, moved = stored[1], stored[3], stored[4]
    db.execute(
        "UPDATE privacy_audit_records SET receipt_canonical = ? WHERE receipt_id = ?",
        (b"{not a receipt", garbled.receipt_id),
    )
    # An older build could store final_bytes up to 512 KiB; the published wire stops at 262,144.
    row = db.execute(
        "SELECT receipt_canonical FROM privacy_audit_records WHERE receipt_id = ?",
        (older.receipt_id,),
    ).fetchone()
    assert row is not None
    shape = json.loads(cast(bytes, row[0]))
    shape["counts"]["final_bytes"] = 300_000
    db.execute(
        "UPDATE privacy_audit_records SET receipt_canonical = ? WHERE receipt_id = ?",
        (canonical_encode(shape), older.receipt_id),
    )
    # A receipt whose own bytes disagree with the column the page is ordered by.
    db.execute(
        "UPDATE privacy_audit_records SET receipt_finished_at = ? WHERE receipt_id = ?",
        (format_rfc3339_millis(_NOW - timedelta(seconds=30)), moved.receipt_id),
    )

    first = asyncio.run(
        audit.list_receipts(
            PrivacyReceiptQuery(limit=3), PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL
        )
    )
    assert first.next_cursor is not None
    second = asyncio.run(
        audit.list_receipts(
            PrivacyReceiptQuery(limit=3, cursor=first.next_cursor),
            PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL,
        )
    )

    assert [view.receipt for view in first.receipts] == [
        _legacy_receipt_view(stored[0]),
        _legacy_receipt_view(stored[2]),
    ]
    assert (first.undecodable_count, first.undecodable_receipt_ids) == (1, (garbled.receipt_id,))
    assert [view.receipt for view in second.receipts] == [_legacy_receipt_view(stored[5])]
    assert (second.undecodable_count, second.undecodable_receipt_ids) == (
        2,
        (older.receipt_id, moved.receipt_id),
    )
    assert second.next_cursor is None
    with pytest.raises(PrivacyAuditUnreadable) as fetched:
        asyncio.run(
            audit.get_receipt(garbled.receipt_id, PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL)
        )
    assert fetched.value.reason == "privacy_audit_local_row_undecodable"
    records = [
        json.loads(line)
        for line in (tmp_path / "service.diagnostics.jsonl").read_text().splitlines()
    ]
    assert [
        (record["operation"], record["reason"], record["request_id"]) for record in records
    ] == [
        (
            "privacy_receipts_list_row_skipped",
            "privacy_audit_local_row_undecodable",
            row.request_id,
        )
        for row in (garbled, older, moved)
    ]
    assert "not a receipt" not in json.dumps(records)


@pytest.mark.parametrize("adapter", ["sqlite", "memory"])
def test_a_bad_cursor_is_the_one_typed_caller_error(adapter: str) -> None:
    if adapter == "sqlite":
        audit: PrivacyAuditPort = CatalogPrivacyAudit(
            _database(),
            _UnusedObjects(),  # type: ignore[arg-type]
            _Key(),
            _Clock(),
        )
    else:
        audit = MemoryPrivacyAudit(
            MemoryPrivacyCatalogState(),
            _UnusedObjects(),  # type: ignore[arg-type]
            _Key(),
            _Clock(),
        )

    with pytest.raises(PrivacyReceiptCursorInvalid):
        asyncio.run(
            audit.list_receipts(
                PrivacyReceiptQuery(cursor="AAAA"), PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL
            )
        )


def test_skipped_row_diagnostics_are_bounded_per_page_while_the_page_names_every_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A heavily corrupt audit listed again and again must not flood the diagnostics ring."""

    import finishup.observability.diagnostics as diagnostics_module

    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)
    db = _database()
    audit = CatalogPrivacyAudit(db, _UnusedObjects(), _Key(), _Clock())  # type: ignore[arg-type]
    stored = [_stored_projection(audit, index) for index in range(1, 9)]
    for receipt in stored:
        db.execute(
            "UPDATE privacy_audit_records SET receipt_canonical = ? WHERE receipt_id = ?",
            (b"[]", receipt.receipt_id),
        )

    page = asyncio.run(
        audit.list_receipts(PrivacyReceiptQuery(), PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL)
    )

    assert page.receipts == ()
    assert page.undecodable_count == 8
    assert page.undecodable_receipt_ids == tuple(receipt.receipt_id for receipt in stored)
    records = (tmp_path / "service.diagnostics.jsonl").read_text().splitlines()
    assert [json.loads(line)["request_id"] for line in records] == [
        receipt.request_id for receipt in stored[:5]
    ]


def _corrupt_columns(
    db: apsw.Connection,
    receipt: LocalDisclosureReceipt,
    *,
    finished_at: str | None = None,
    receipt_id: str | None = None,
) -> None:
    """Corrupt a row's indexed columns the way disk damage or tampering could; the schema
    constrains their type (STRICT TEXT) and presence, not their format."""

    db.execute(
        """UPDATE privacy_audit_records
           SET receipt_finished_at = coalesce(?, receipt_finished_at),
               receipt_id = coalesce(?, receipt_id)
           WHERE receipt_id = ?""",
        (finished_at, receipt_id, receipt.receipt_id),
    )


def _page_through(
    audit: CatalogPrivacyAudit, limit: int
) -> tuple[list[str], list[PrivacyReceiptPage]]:
    pages: list[PrivacyReceiptPage] = []
    cursor: str | None = None
    while True:
        page = asyncio.run(
            audit.list_receipts(
                PrivacyReceiptQuery(limit=limit, cursor=cursor),
                PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL,
            )
        )
        pages.append(page)
        assert len(pages) <= 20, "paging must always make progress"
        cursor = page.next_cursor
        if cursor is None:
            return [
                view.receipt.receipt_id for view in (v for p in pages for v in p.receipts)
            ], pages


def test_a_corrupt_row_at_either_end_of_a_page_never_strands_the_pages_behind_it() -> None:
    """The cursor carries the last row's key as stored, so a corrupt row can end one page and
    start the next while every readable receipt after it stays reachable and the skip is named.
    """

    db = _database()
    audit = CatalogPrivacyAudit(db, _UnusedObjects(), _Key(), _Clock())  # type: ignore[arg-type]
    stored = [_stored_projection(audit, index) for index in range(1, 9)]
    ending, starting = stored[2], stored[3]
    # Last row of page one: neither indexed column is canonical any more, but both still sort
    # where the row was.
    _corrupt_columns(
        db,
        ending,
        finished_at=format_rfc3339_millis(ending.finished_at) + "~corrupt",
        receipt_id="egr_corrupted",
    )
    # First row of page two: only its finish time is damaged, so its structural id is named.
    _corrupt_columns(
        db, starting, finished_at=format_rfc3339_millis(starting.finished_at) + "~corrupt"
    )

    listed, pages = _page_through(audit, 3)

    readable = [receipt for receipt in stored if receipt not in (ending, starting)]
    assert listed == [receipt.receipt_id for receipt in readable]
    assert [(page.undecodable_count, page.undecodable_receipt_ids) for page in pages] == [
        (1, ()),
        (1, (starting.receipt_id,)),
        (0, ()),
    ]


def test_a_row_whose_finish_time_is_not_a_timestamp_is_disclosed_not_dropped() -> None:
    """Text such as ``zzzz`` sorts above every snapshot bound; it must still be listed as
    unreadable instead of silently falling outside the listing."""

    db = _database()
    audit = CatalogPrivacyAudit(db, _UnusedObjects(), _Key(), _Clock())  # type: ignore[arg-type]
    stored = [_stored_projection(audit, index) for index in range(1, 4)]
    _corrupt_columns(db, stored[1], finished_at="zzzz-not-a-timestamp")

    listed, pages = _page_through(audit, 1)

    assert listed == [stored[0].receipt_id, stored[2].receipt_id]
    assert pages[0].undecodable_receipt_ids == (stored[1].receipt_id,)
    assert sum(page.undecodable_count for page in pages) == 1


def test_a_cursor_this_store_minted_with_a_non_text_position_is_a_store_fault() -> None:
    """Only this store can mint a cursor whose MAC and query digest verify, so a malformed one
    is the store's integrity fault -- never the caller's ``invalid_request``."""

    db = _database()
    audit = CatalogPrivacyAudit(db, _UnusedObjects(), _Key(), _Clock())  # type: ignore[arg-type]
    for index in range(1, 4):
        _stored_projection(audit, index)
    first = asyncio.run(
        audit.list_receipts(
            PrivacyReceiptQuery(limit=1), PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL
        )
    )
    assert first.next_cursor is not None
    payload = dict(audit._decode_cursor(first.next_cursor))  # pyright: ignore[reportPrivateUsage]
    payload["after_at"] = 17
    minted = audit._encode_cursor(payload)  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(PrivacyAuditUnreadable) as raised:
        asyncio.run(
            audit.list_receipts(
                PrivacyReceiptQuery(limit=1, cursor=minted),
                PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL,
            )
        )

    assert raised.value.reason == "privacy_audit_page_invariant_violated"


def test_sqlite_status_reports_the_grant_a_pending_carry_forward_will_create() -> None:
    """Issue #982 review: the derivation matches what carry-forward then writes."""

    from finishup.application.privacy_policy import credential_heuristic_state
    from finishup.domain.privacy import CredentialHeuristic

    db = _database()
    store = CatalogPrivacyPolicyStore(db, _Clock())
    machine = replace(minimal_external_policy(), credential_heuristic=CredentialHeuristic.DISABLED)
    repository = AuthorizationScope(
        AuthorizationScopeKind.WORKSPACE, _INSTALLATION, "hmac-sha256:" + "1" * 64
    )

    async def run() -> tuple[object, object]:
        await store.seed_if_absent(machine)
        before = credential_heuristic_state(await store.repository_authority(repository))
        carried = await store.carry_forward_repository_authority(repository)
        return before, credential_heuristic_state(carried)

    before, after = asyncio.run(run())
    assert (before.repository, before.machine_default) == ("disabled", "disabled")  # type: ignore[attr-defined]
    assert after.repository == before.repository  # type: ignore[attr-defined]
