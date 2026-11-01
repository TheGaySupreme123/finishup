"""Unit tests for the in-memory ObservationPort adapter."""

from __future__ import annotations

import asyncio

import pytest

from finishup.adapters.memory.observation import MemoryObservationStore
from finishup.domain.observation import (
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
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.errors import PublicOperationError

_WORKSPACE = "hmac-sha256:" + "1" * 64
_SESSION = "hmac-sha256:" + "2" * 64
_SOURCE = "hmac-sha256:" + "3" * 64
_TIME = Timestamp("2026-07-22T21:10:00.000Z")


def _cursor(*, generation: int = 1, byte_pos: int = 10, event_pos: int = 1) -> ObservationCursor:
    return ObservationCursor(
        source_generation=generation,
        byte_position=byte_pos,
        event_position=event_pos,
        last_source_commitment=_SOURCE,
        mapping_version="codex-obs-1",
    )


def _envelope(
    *,
    cursor: ObservationCursor | None = None,
    receipt_time: Timestamp = _TIME,
    content_object_refs: tuple[str, ...] = (),
) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=_SESSION,
        event_kind="PostToolUse",
        source_identity="hook:evt-1",
        source=ObservationSource.CODEX_HOOK,
        cursor=cursor or _cursor(),
        receipt_time=receipt_time,
        structural_payload=JsonObject({"tool_name": "shell", "exit_status": 0}),
        content_object_refs=content_object_refs,
        gap_codes=(),
    )


def test_ingest_fails_closed_without_consent() -> None:
    async def run() -> None:
        store = MemoryObservationStore()
        result = await store.ingest(_envelope())
        assert result.disposition is ObservationIngestDisposition.REJECTED
        assert result.reason == ObservationGapCode.CONSENT_MISSING.value

    asyncio.run(run())


def test_consent_pause_resume_revoke_and_dedup() -> None:
    async def run() -> None:
        store = MemoryObservationStore()
        store.grant_consent(_WORKSPACE, _TIME)
        store.bind_session(_WORKSPACE, _SESSION)

        accepted = await store.ingest(_envelope())
        assert accepted.disposition is ObservationIngestDisposition.ACCEPTED
        duplicate = await store.ingest(_envelope())
        assert duplicate.disposition is ObservationIngestDisposition.DUPLICATE

        paused = await store.pause(ObservationControlCommand(_WORKSPACE))
        assert paused.lifecycle is ObservationLifecycle.STOPPED
        rejected = await store.ingest(_envelope(cursor=_cursor(byte_pos=20, event_pos=2)))
        assert rejected.disposition is ObservationIngestDisposition.REJECTED

        resumed = await store.resume(ObservationControlCommand(_WORKSPACE))
        assert resumed.lifecycle is ObservationLifecycle.ACTIVE
        again = await store.ingest(_envelope(cursor=_cursor(byte_pos=20, event_pos=2)))
        assert again.disposition is ObservationIngestDisposition.ACCEPTED

        revoked = await store.revoke(ObservationRevokeCommand(_WORKSPACE))
        assert revoked.lifecycle is ObservationLifecycle.STOPPED
        after_revoke = await store.ingest(_envelope(cursor=_cursor(byte_pos=30, event_pos=3)))
        assert after_revoke.disposition is ObservationIngestDisposition.REJECTED
        assert after_revoke.reason == ObservationGapCode.CONSENT_REVOKED.value

        status = await store.status(ObservationStatusQuery(_WORKSPACE))
        assert status.source_coverage[ObservationSource.CODEX_HOOK] is True
        assert len(store._state.envelopes) == 2  # pyright: ignore[reportPrivateUsage]

    asyncio.run(run())


def test_resume_without_consent_fails() -> None:
    async def run() -> None:
        store = MemoryObservationStore()
        with pytest.raises(PublicOperationError):
            await store.resume(ObservationControlCommand(_WORKSPACE))

    asyncio.run(run())


def test_content_profiles_are_idempotent_and_revoke_clears_them() -> None:
    store = MemoryObservationStore()
    store.grant_consent(
        _WORKSPACE,
        _TIME,
        content_capture_profiles=(CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,),
    )
    store.enable_content_capture(_WORKSPACE, CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID)
    store.enable_content_capture(_WORKSPACE, CURSOR_ORDINARY_OBSERVATION_PROFILE_ID)
    store.enable_content_capture(_WORKSPACE, CURSOR_ORDINARY_OBSERVATION_PROFILE_ID)
    assert store.content_capture_profiles(_WORKSPACE) == (
        CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    )

    store.disable_content_capture(_WORKSPACE, CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID)
    assert store.content_capture_profiles(_WORKSPACE) == (CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,)
    asyncio.run(store.revoke(ObservationRevokeCommand(_WORKSPACE)))
    assert store.content_capture_profiles(_WORKSPACE) == ()


def test_successful_cursor_advance_clears_stale_gap_despite_future_receipt_time() -> None:
    async def run() -> None:
        store = MemoryObservationStore()
        store.grant_consent(_WORKSPACE, _TIME)
        store.bind_session(_WORKSPACE, _SESSION)
        assert (await store.ingest(_envelope(cursor=_cursor(event_pos=2)))).disposition is (
            ObservationIngestDisposition.ACCEPTED
        )
        stale = await store.ingest(
            _envelope(
                cursor=_cursor(event_pos=1),
                receipt_time=Timestamp("2099-01-01T00:00:00.000Z"),
            )
        )
        assert stale.reason == ObservationGapCode.CURSOR_STALE.value
        assert (
            ObservationGapCode.CURSOR_STALE.value
            in (await store.status(ObservationStatusQuery(_WORKSPACE))).gaps
        )

        advanced = await store.ingest(_envelope(cursor=_cursor(event_pos=3)))
        assert advanced.disposition is ObservationIngestDisposition.ACCEPTED
        assert (
            ObservationGapCode.CURSOR_STALE.value
            not in (await store.status(ObservationStatusQuery(_WORKSPACE))).gaps
        )
        history = store._state.gaps[_WORKSPACE][  # pyright: ignore[reportPrivateUsage]
            ObservationGapCode.CURSOR_STALE.value
        ]
        assert history.first_seen == Timestamp("2099-01-01T00:00:00.000Z")
        assert history.last_seen == Timestamp("2099-01-01T00:00:00.000Z")
        assert history.active is False

    asyncio.run(run())


def test_captured_content_clears_capture_unavailable_gap() -> None:
    async def run() -> None:
        store = MemoryObservationStore()
        store.grant_consent(_WORKSPACE, _TIME)
        store.bind_session(_WORKSPACE, _SESSION)
        gap = _envelope()
        gap = ObservationEnvelope(
            session_commitment=gap.session_commitment,
            event_kind=gap.event_kind,
            source_identity=gap.source_identity,
            source=gap.source,
            cursor=gap.cursor,
            receipt_time=gap.receipt_time,
            structural_payload=gap.structural_payload,
            content_object_refs=gap.content_object_refs,
            gap_codes=(ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,),
        )
        assert (await store.ingest(gap)).disposition is ObservationIngestDisposition.ACCEPTED
        assert (
            ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
            in (await store.status(ObservationStatusQuery(_WORKSPACE))).gaps
        )

        captured = await store.ingest(
            _envelope(
                cursor=_cursor(event_pos=2),
                content_object_refs=("obj_00000000-0000-4000-8000-000000000001",),
            )
        )
        assert captured.disposition is ObservationIngestDisposition.ACCEPTED
        assert (
            ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
            not in (await store.status(ObservationStatusQuery(_WORKSPACE))).gaps
        )
        history = store._state.gaps[_WORKSPACE][  # pyright: ignore[reportPrivateUsage]
            ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
        ]
        assert history.active is False

    asyncio.run(run())
