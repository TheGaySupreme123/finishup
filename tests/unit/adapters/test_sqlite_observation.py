"""Unit tests for SQLite ObservationPort over migration 0002 tables."""

from __future__ import annotations

import asyncio
from dataclasses import replace

import apsw
import pytest

from yoetz.adapters.sqlite import connection as connection_module
from yoetz.adapters.sqlite import migrations as migrations_module
from yoetz.adapters.sqlite.migrations import initialize_bundle
from yoetz.adapters.sqlite.observation import SqliteObservationStore
from yoetz.domain.observation import (
    ObservationCaptureTicket,
    ObservationControlCommand,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationLifecycle,
    ObservationRevokeCommand,
    ObservationSource,
    ObservationStatusQuery,
)
from yoetz.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from yoetz.domain.values import JsonObject, Timestamp
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError

_WORKSPACE = "hmac-sha256:" + "1" * 64
_SESSION = "hmac-sha256:" + "2" * 64
_SOURCE = "hmac-sha256:" + "3" * 64
_TIME = Timestamp("2026-07-22T21:10:00.000Z")
_TASK = "tsk_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_YOETZ_SESSION = "ses_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def _store() -> SqliteObservationStore:
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": _TASK, "owner_generation": "1"})
    # Exercise the production SQL guard: plain APSW missed the #616 consent
    # schema-probe failure across structural and both native content profiles.
    db.set_authorizer(connection_module._writer_authorizer)  # pyright: ignore[reportPrivateUsage]
    return SqliteObservationStore(db)


def test_guarded_legacy_bundle_keeps_structural_consent_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        # Keep this fixture explicitly at the last pre-native-content schema;
        # a tail slice would silently move the historical cutoff when a
        # migration is added.
        migrations_module,
        "BUNDLE_MIGRATIONS",
        tuple(
            migration
            for migration in migrations_module.BUNDLE_MIGRATIONS
            if int(migration.version) <= 9
        ),
    )
    store = _store()
    store.grant_consent(_WORKSPACE, _TIME)
    store.bind_session(_WORKSPACE, _SESSION)
    assert store.content_capture_profiles(_WORKSPACE) == ()
    with pytest.raises(PublicOperationError) as rejected:
        store.enable_content_capture(_WORKSPACE, CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID)
    assert rejected.value.code is PublicErrorCode.INVALID_REQUEST
    assert rejected.value.retryable is False
    assert store.content_capture_profiles(_WORKSPACE) == ()


def _cursor(*, generation: int = 1, byte_pos: int = 10, event_pos: int = 1) -> ObservationCursor:
    return ObservationCursor(
        source_generation=generation,
        byte_position=byte_pos,
        event_position=event_pos,
        last_source_commitment=_SOURCE,
        mapping_version="codex-obs-1",
    )


def _envelope(*, cursor: ObservationCursor | None = None) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=_SESSION,
        event_kind="PostToolUse",
        source_identity="hook:evt-1",
        source=ObservationSource.CODEX_HOOK,
        cursor=cursor or _cursor(),
        receipt_time=_TIME,
        structural_payload=JsonObject({"tool_name": "shell", "exit_status": 0}),
        content_object_refs=(),
        gap_codes=(),
    )


def test_capture_ticket_staging_round_trip_and_revocation() -> None:
    store = _store()
    ticket = ObservationCaptureTicket(
        workspace_commitment=_WORKSPACE,
        task_id=_TASK,
        yoetz_session_id=_YOETZ_SESSION,
        session_commitment=_SESSION,
        source=ObservationSource.CLAUDE_HOOK,
        source_identity="hook:ticket-1",
        cursor=_cursor(),
        logical_identity="sha256:" + "a" * 64,
        content_capture_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        authority_generation="sha256:" + "b" * 64,
        object_ids=(),
        captured_at=_TIME,
        state="staging",
    )
    store.record_capture_ticket(ticket)
    assert (
        store.load_capture_ticket(workspace=_WORKSPACE, logical_identity=ticket.logical_identity)
        == ticket
    )

    store.tombstone_capture_ticket(ticket)
    revoked = store.load_capture_ticket(
        workspace=_WORKSPACE, logical_identity=ticket.logical_identity
    )
    assert revoked is not None
    assert revoked.state == "revoked"
    assert revoked.object_ids == ()


def test_capture_ticket_quota_counts_only_active_handoffs() -> None:
    store = _store()
    base = ObservationCaptureTicket(
        workspace_commitment=_WORKSPACE,
        task_id=_TASK,
        yoetz_session_id=_YOETZ_SESSION,
        session_commitment=_SESSION,
        source=ObservationSource.CLAUDE_HOOK,
        source_identity="hook:quota-0",
        cursor=_cursor(),
        logical_identity="sha256:" + "0" * 64,
        content_capture_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        authority_generation="sha256:" + "b" * 64,
        object_ids=(),
        captured_at=_TIME,
        state="staging",
    )

    tickets: list[ObservationCaptureTicket] = []
    for index in range(512):
        ticket = replace(
            base,
            source_identity=f"hook:quota-{index}",
            cursor=_cursor(byte_pos=10 + index),
            logical_identity=f"sha256:{index:064x}",
        )
        store.record_capture_ticket(ticket)
        tickets.append(ticket)

    exhausted = replace(
        base,
        source_identity="hook:quota-512",
        cursor=_cursor(byte_pos=522),
        logical_identity=f"sha256:{512:064x}",
    )
    with pytest.raises(PublicOperationError) as capacity:
        store.record_capture_ticket(exhausted)
    assert capacity.value.code is PublicErrorCode.LIMIT_EXCEEDED

    store.tombstone_capture_ticket(tickets[0])
    store.record_capture_ticket(exhausted)
    assert (
        store.load_capture_ticket(workspace=_WORKSPACE, logical_identity=exhausted.logical_identity)
        is not None
    )


def test_sqlite_consent_ingest_dedup_and_revoke() -> None:
    async def run() -> None:
        store = _store()
        store.grant_consent(_WORKSPACE, _TIME)
        store.bind_session(_WORKSPACE, _SESSION)
        accepted = await store.ingest(_envelope())
        assert accepted.disposition is ObservationIngestDisposition.ACCEPTED
        duplicate = await store.ingest(_envelope())
        assert duplicate.disposition is ObservationIngestDisposition.DUPLICATE
        status = await store.status(ObservationStatusQuery(_WORKSPACE))
        assert status.source_coverage[ObservationSource.CODEX_HOOK] is True
        assert status.lifecycle is ObservationLifecycle.ACTIVE
        envelopes = store.list_envelopes(_WORKSPACE)
        assert len(envelopes) == 1
        revoked = await store.revoke(ObservationRevokeCommand(_WORKSPACE))
        assert revoked.lifecycle is ObservationLifecycle.STOPPED
        after = await store.ingest(_envelope(cursor=_cursor(byte_pos=20, event_pos=2)))
        assert after.disposition is ObservationIngestDisposition.REJECTED
        assert after.reason == ObservationGapCode.CONSENT_REVOKED.value
        # Evidence retained after revoke.
        assert len(store.list_envelopes(_WORKSPACE)) == 1

    asyncio.run(run())


def test_sqlite_pause_resume() -> None:
    async def run() -> None:
        store = _store()
        store.grant_consent(_WORKSPACE, _TIME)
        store.bind_session(_WORKSPACE, _SESSION)
        await store.ingest(_envelope())
        paused = await store.pause(ObservationControlCommand(_WORKSPACE))
        assert paused.lifecycle is ObservationLifecycle.STOPPED
        rejected = await store.ingest(_envelope(cursor=_cursor(byte_pos=20, event_pos=2)))
        assert rejected.disposition is ObservationIngestDisposition.REJECTED
        resumed = await store.resume(ObservationControlCommand(_WORKSPACE))
        assert resumed.lifecycle is ObservationLifecycle.ACTIVE
        again = await store.ingest(_envelope(cursor=_cursor(byte_pos=20, event_pos=2)))
        assert again.disposition is ObservationIngestDisposition.ACCEPTED

    asyncio.run(run())


def test_sqlite_content_profiles_survive_pause_and_clear_on_revoke() -> None:
    async def run() -> None:
        store = _store()
        store.grant_consent(
            _WORKSPACE,
            _TIME,
            content_capture_profiles=(CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,),
        )
        assert store.content_capture_profiles(_WORKSPACE) == (
            CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        )
        store.enable_content_capture(_WORKSPACE, CURSOR_ORDINARY_OBSERVATION_PROFILE_ID)
        store.enable_content_capture(_WORKSPACE, CURSOR_ORDINARY_OBSERVATION_PROFILE_ID)
        assert store.content_capture_profiles(_WORKSPACE) == (
            CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        )
        await store.pause(ObservationControlCommand(_WORKSPACE))
        assert store.content_capture_profiles(_WORKSPACE) == (
            CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        )
        await store.resume(ObservationControlCommand(_WORKSPACE))
        store.disable_content_capture(_WORKSPACE, CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID)
        assert store.content_capture_profiles(_WORKSPACE) == (
            CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        )
        await store.revoke(ObservationRevokeCommand(_WORKSPACE))
        assert store.content_capture_profiles(_WORKSPACE) == ()

    asyncio.run(run())


def test_sqlite_resume_without_consent_fails() -> None:
    async def run() -> None:
        store = _store()
        with pytest.raises(PublicOperationError):
            await store.resume(ObservationControlCommand(_WORKSPACE))

    asyncio.run(run())


def test_record_logical_identity_claim_idempotence_union_and_conflict() -> None:
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    logical_identity = "sha256:" + "a" * 64
    materialization_digest = "sha256:" + "b" * 64
    operation_id = "op_" + "1" * 32
    mapping_version = "obs-ledger/1.2.0"

    def record(*, source_mask: int, digest: str = materialization_digest) -> None:
        store.record_logical_identity_claim(
            workspace=_WORKSPACE,
            logical_identity=logical_identity,
            materialization_digest=digest,
            operation_id=operation_id,
            mapping_version=mapping_version,
            source_mask=source_mask,
            materialized_at=_TIME,
        )

    record(source_mask=1)
    # A replay of the same source is idempotent.
    record(source_mask=1)
    # The other source's copy of the same materialization unions coverage.
    record(source_mask=2)
    row = db.execute(
        "SELECT source_mask FROM observation_logical_identity "
        "WHERE workspace_commitment=? AND logical_identity=?",
        (_WORKSPACE, logical_identity),
    ).fetchone()
    assert row == (3,)
    assert store.load_logical_identity_claim(
        workspace=_WORKSPACE,
        logical_identity=logical_identity,
    ) == (materialization_digest, operation_id, mapping_version)

    # A different materialization of the same claim key is corruption.
    with pytest.raises(PublicOperationError) as conflict:
        record(source_mask=1, digest="sha256:" + "c" * 64)
    assert conflict.value.code is PublicErrorCode.STORAGE_CORRUPT
    assert conflict.value.retryable is False

    # Only the two per-source masks are valid inputs; 3 is a stored union.
    with pytest.raises(PublicOperationError) as invalid:
        record(source_mask=3)
    assert invalid.value.code is PublicErrorCode.INVALID_REQUEST


_SESSION_B = "hmac-sha256:" + "4" * 64


def _session_envelope(
    session: str,
    identity: str,
    ordinal: int,
    *,
    gaps: tuple[str, ...] = (),
) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=session,
        event_kind="PostToolUse",
        source_identity=identity,
        source=ObservationSource.CODEX_HOOK,
        cursor=_cursor(byte_pos=10 * ordinal, event_pos=ordinal),
        receipt_time=_TIME,
        structural_payload=JsonObject({"tool_name": "shell", "exit_status": 0}),
        content_object_refs=(),
        gap_codes=gaps,
    )


def test_session_scoped_envelopes_and_status_exclude_other_sessions() -> None:
    """#352: mapped advice inputs must not see another session's envelopes or gaps."""

    async def run() -> None:
        store = _store()
        store.grant_consent(_WORKSPACE, _TIME)
        store.bind_session(_WORKSPACE, _SESSION)
        store.bind_session(_WORKSPACE, _SESSION_B)
        # Session A carries degradation; session B is healthy.
        degraded = await store.ingest(
            _session_envelope(
                _SESSION,
                "hook:degraded-a",
                1,
                gaps=(
                    ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value,
                    ObservationGapCode.SOURCE_LAG.value,
                ),
            )
        )
        assert degraded.disposition is ObservationIngestDisposition.ACCEPTED
        healthy = await store.ingest(_session_envelope(_SESSION_B, "hook:healthy-b", 1))
        assert healthy.disposition is ObservationIngestDisposition.ACCEPTED

        workspace_wide = store.list_envelopes(_WORKSPACE)
        assert len(workspace_wide) == 2
        only_b = store.list_envelopes_for_session(_WORKSPACE, _SESSION_B)
        assert [env.source_identity for env in only_b] == ["hook:healthy-b"]

        status_b = await store.status_for_session(_WORKSPACE, _SESSION_B)
        assert status_b.gaps == ()
        assert status_b.lifecycle is ObservationLifecycle.ACTIVE
        status_a = await store.status_for_session(_WORKSPACE, _SESSION)
        assert ObservationGapCode.SOURCE_LAG.value in status_a.gaps
        assert ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value in status_a.gaps
        # The workspace aggregate still retains A's history for the operator surface.
        aggregate = await store.status(ObservationStatusQuery(_WORKSPACE))
        assert ObservationGapCode.SOURCE_LAG.value in aggregate.gaps

    asyncio.run(run())


def test_session_status_clears_current_gap_without_clearing_other_sessions() -> None:
    """Historical gap rows remain append-only while current health recovers per session."""

    async def run() -> None:
        store = _store()
        store.grant_consent(_WORKSPACE, _TIME)
        store.bind_session(_WORKSPACE, _SESSION)
        store.bind_session(_WORKSPACE, _SESSION_B)
        degraded_a = await store.ingest(
            _session_envelope(
                _SESSION,
                "hook:degraded-a-current",
                1,
                gaps=(ObservationGapCode.SOURCE_LAG.value,),
            )
        )
        degraded_b = await store.ingest(
            _session_envelope(
                _SESSION_B,
                "hook:degraded-b-current",
                1,
                gaps=(ObservationGapCode.SOURCE_LAG.value,),
            )
        )
        assert degraded_a.disposition is ObservationIngestDisposition.ACCEPTED
        assert degraded_b.disposition is ObservationIngestDisposition.ACCEPTED

        recovered_b = await store.ingest(
            _session_envelope(_SESSION_B, "hook:recovered-b-current", 2)
        )
        assert recovered_b.disposition is ObservationIngestDisposition.ACCEPTED
        status_a = await store.status_for_session(_WORKSPACE, _SESSION)
        status_b = await store.status_for_session(_WORKSPACE, _SESSION_B)
        assert ObservationGapCode.SOURCE_LAG.value in status_a.gaps
        assert ObservationGapCode.SOURCE_LAG.value not in status_b.gaps
        aggregate = await store.status(ObservationStatusQuery(_WORKSPACE))
        assert ObservationGapCode.SOURCE_LAG.value in aggregate.gaps

        recovered_a = await store.ingest(_session_envelope(_SESSION, "hook:recovered-a-current", 2))
        assert recovered_a.disposition is ObservationIngestDisposition.ACCEPTED
        assert (
            ObservationGapCode.SOURCE_LAG.value
            not in (await store.status_for_session(_WORKSPACE, _SESSION)).gaps
        )
        assert (
            ObservationGapCode.SOURCE_LAG.value
            not in (await store.status(ObservationStatusQuery(_WORKSPACE))).gaps
        )
        # Recovery changes only the current projection; all observations remain.
        assert len(store.list_envelopes(_WORKSPACE)) == 4

    asyncio.run(run())


def test_sqlite_standing_gaps_do_not_degrade_current_lifecycle() -> None:
    """Coverage-only gaps remain visible without becoming false health failures (#974)."""

    async def run() -> None:
        store = _store()
        store.grant_consent(_WORKSPACE, _TIME)
        store.bind_session(_WORKSPACE, _SESSION)
        standing = tuple(
            sorted(
                (
                    ObservationGapCode.UNPAIRED_EVENT.value,
                    ObservationGapCode.TRUNCATED_PAYLOAD.value,
                    ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                    "pending_attempt_expired",
                    ObservationGapCode.CONTENT_UNSELECTED.value,
                ),
                key=str.encode,
            )
        )
        accepted = await store.ingest(
            _session_envelope(_SESSION, "hook:standing", 1, gaps=standing)
        )
        assert accepted.disposition is ObservationIngestDisposition.ACCEPTED

        status = await store.status_for_session(_WORKSPACE, _SESSION)
        assert set(standing) <= set(status.gaps)
        assert status.lifecycle is ObservationLifecycle.ACTIVE

        material = await store.ingest(
            _session_envelope(
                _SESSION,
                "hook:material",
                2,
                gaps=(ObservationGapCode.SOURCE_LAG.value,),
            )
        )
        assert material.disposition is ObservationIngestDisposition.ACCEPTED
        assert (
            await store.status_for_session(_WORKSPACE, _SESSION)
        ).lifecycle is ObservationLifecycle.DEGRADED

    asyncio.run(run())


def test_codex_session_commitment_for_session_recovers_historical_route() -> None:
    store = _store()
    store.grant_consent(_WORKSPACE, _TIME)
    store.record_workspace_session_route(
        workspace=_WORKSPACE,
        yoetz_session_id="ses_10000000-0000-4000-8000-000000000001",
        yoetz_task_id="tsk_10000000-0000-4000-8000-000000000001",
        yoetz_writer_id="wtr_10000000-0000-4000-8000-000000000001",
        codex_session_commitment=_SESSION,
        bound_at=_TIME,
    )
    # Binding a newer session keeps the older route active; both task/session
    # lanes remain available for recovery and concurrent verification.
    store.record_workspace_session_route(
        workspace=_WORKSPACE,
        yoetz_session_id="ses_10000000-0000-4000-8000-000000000002",
        yoetz_task_id="tsk_10000000-0000-4000-8000-000000000002",
        yoetz_writer_id="wtr_10000000-0000-4000-8000-000000000002",
        codex_session_commitment=_SESSION_B,
        bound_at=_TIME,
    )
    assert (
        store.codex_session_commitment_for_session(
            workspace=_WORKSPACE,
            yoetz_session_id="ses_10000000-0000-4000-8000-000000000001",
        )
        == _SESSION
    )
    assert (
        store.workspace_for_yoetz_session("ses_10000000-0000-4000-8000-000000000001") == _WORKSPACE
    )
    assert (
        store.codex_session_commitment_for_session(
            workspace=_WORKSPACE,
            yoetz_session_id="ses_10000000-0000-4000-8000-000000000002",
        )
        == _SESSION_B
    )


def test_workspace_session_route_commitment_is_first_writer_fence() -> None:
    store = _store()
    store.grant_consent(_WORKSPACE, _TIME)
    yoetz_session = "ses_10000000-0000-4000-8000-000000000003"
    assert (
        store.record_workspace_session_route(
            workspace=_WORKSPACE,
            yoetz_session_id=yoetz_session,
            yoetz_task_id=_TASK,
            yoetz_writer_id="wtr_10000000-0000-4000-8000-000000000003",
            codex_session_commitment=_SESSION,
            bound_at=_TIME,
        )
        is True
    )
    # A late predecessor may race the first route write. The conflict is a no-op and
    # reports failure so callers cannot treat the stale envelope as current activity.
    assert (
        store.record_workspace_session_route(
            workspace=_WORKSPACE,
            yoetz_session_id=yoetz_session,
            yoetz_task_id=_TASK,
            yoetz_writer_id="wtr_10000000-0000-4000-8000-000000000004",
            codex_session_commitment=_SESSION_B,
            bound_at=_TIME,
        )
        is False
    )
    assert (
        store.codex_session_commitment_for_session(
            workspace=_WORKSPACE,
            yoetz_session_id=yoetz_session,
        )
        == _SESSION
    )


def test_workspace_routes_keep_unrelated_sessions_active() -> None:
    """A shared source workspace may have multiple task/session lanes (#498)."""

    store = _store()
    store.grant_consent(_WORKSPACE, _TIME)
    for yoetz_session, session, task, writer in (
        (
            "ses_10000000-0000-4000-8000-000000000001",
            _SESSION,
            "tsk_10000000-0000-4000-8000-000000000011",
            "wtr_10000000-0000-4000-8000-000000000011",
        ),
        (
            "ses_10000000-0000-4000-8000-000000000002",
            _SESSION_B,
            "tsk_10000000-0000-4000-8000-000000000012",
            "wtr_10000000-0000-4000-8000-000000000012",
        ),
    ):
        store.record_workspace_session_route(
            workspace=_WORKSPACE,
            yoetz_session_id=yoetz_session,
            yoetz_task_id=task,
            yoetz_writer_id=writer,
            codex_session_commitment=session,
            bound_at=_TIME,
        )
    rows = store._db.execute(  # pyright: ignore[reportPrivateUsage]
        "SELECT yoetz_session_id,active FROM observation_workspace_session_routes "
        "WHERE workspace_commitment=? ORDER BY yoetz_session_id",
        (_WORKSPACE,),
    ).fetchall()
    assert rows == [
        ("ses_10000000-0000-4000-8000-000000000001", 1),
        ("ses_10000000-0000-4000-8000-000000000002", 1),
    ]


def test_bounded_envelope_window_filters_session_before_selecting_latest_rows() -> None:
    async def run() -> None:
        store = _store()
        store.grant_consent(_WORKSPACE, _TIME)
        store.bind_session(_WORKSPACE, _SESSION)
        store.bind_session(_WORKSPACE, _SESSION_B)
        for ordinal in range(1, 5):
            for session, prefix in ((_SESSION, "a"), (_SESSION_B, "b")):
                result = await store.ingest(
                    _session_envelope(session, f"hook:{prefix}-{ordinal}", ordinal)
                )
                assert result.disposition is ObservationIngestDisposition.ACCEPTED
        selected = store.list_envelopes_for_session(_WORKSPACE, _SESSION, limit=2)
        assert [item.source_identity for item in selected] == ["hook:a-3", "hook:a-4"]
        assert len(store.list_envelopes_for_session(_WORKSPACE, _SESSION)) == 4
        assert [item.source_identity for item in store.list_envelopes(_WORKSPACE, limit=2)] == [
            "hook:a-4",
            "hook:b-4",
        ]
        with pytest.raises(ValueError, match="observation_envelope_limit_invalid"):
            store.list_envelopes_for_session(_WORKSPACE, _SESSION, limit=257)

    asyncio.run(run())


def test_content_ref_lookup_survives_real_retention_and_keeps_session_fence() -> None:
    """Real ingest must keep provenance after routine events roll over the ring."""

    async def run() -> None:
        store = _store()
        store.grant_consent(_WORKSPACE, _TIME)
        store.bind_session(_WORKSPACE, _SESSION)
        store.bind_session(_WORKSPACE, _SESSION_B)
        early_object = "obj_00000000-0000-4000-8000-000000000883"
        early = replace(
            _session_envelope(_SESSION, "hook:early-edit", 1),
            content_object_refs=(early_object,),
        )
        assert (await store.ingest(early)).disposition is ObservationIngestDisposition.ACCEPTED
        for ordinal in range(2, 302):
            await store.ingest(_session_envelope(_SESSION, f"hook:later-{ordinal}", ordinal))
        await store.ingest(
            replace(
                _session_envelope(_SESSION_B, "hook:other-session", 1),
                content_object_refs=(early_object,),
            )
        )
        assert len(store.list_envelopes(_WORKSPACE)) == 256
        found = store.list_envelopes_for_content_refs(_WORKSPACE, _SESSION, (early_object,))
        assert [item.source_identity for item in found] == ["hook:early-edit"]
        assert store.list_envelopes_for_content_refs(_WORKSPACE, _SESSION, ()) == ()
        with pytest.raises(ValueError, match="observation_envelope_limit_invalid"):
            store.list_envelopes_for_content_refs(_WORKSPACE, _SESSION, (early_object,), limit=0)

    asyncio.run(run())


def test_capture_retention_reservation_is_bounded_and_keeps_recent_structure() -> None:
    async def run() -> None:
        store = _store()
        store.grant_consent(_WORKSPACE, _TIME)
        store.bind_session(_WORKSPACE, _SESSION)
        for ordinal in range(1, 301):
            await store.ingest(
                replace(
                    _session_envelope(_SESSION, f"hook:capture-{ordinal}", ordinal),
                    content_object_refs=(f"obj_00000000-0000-4000-8000-{ordinal:012d}",),
                )
            )
        for ordinal in range(301, 601):
            await store.ingest(_session_envelope(_SESSION, f"hook:recent-{ordinal}", ordinal))
        retained = store.list_envelopes(_WORKSPACE)
        assert len(retained) == 256
        assert sum(bool(item.content_object_refs) for item in retained) == 64
        assert retained[-1].source_identity == "hook:recent-600"
        assert retained[0].source_identity == "hook:capture-237"

    asyncio.run(run())
