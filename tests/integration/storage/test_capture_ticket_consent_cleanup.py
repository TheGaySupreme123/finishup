"""Consent transitions persistently fence unfinished native capture tickets."""

from __future__ import annotations

import asyncio
from pathlib import Path

import apsw

from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.observation import SqliteObservationStore
from finishup.domain.observation import ObservationRevokeCommand
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.domain.values import Timestamp
from finishup.protocol.canonical import canonical_encode

_WORKSPACE = "hmac-sha256:" + "1" * 64
_SESSION = "hmac-sha256:" + "2" * 64
_SOURCE = "hmac-sha256:" + "3" * 64
_TASK = "tsk_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_FINISHUP_SESSION = "ses_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
_TIME = Timestamp("2026-09-06T10:00:00.000Z")


def _ticket_row(
    db: apsw.Connection,
    *,
    profile: str,
    ticket_number: int,
    state: str = "pending",
) -> None:
    """Insert only the metadata needed to exercise the consent fence.

    The deliberately incomplete pending rows also prove revocation does not
    depend on opening content or successfully decoding a capture manifest.
    """

    values: dict[str, str | int | bytes] = {
        "ticket_id": "sha256:" + f"{ticket_number:064x}",
        "workspace_commitment": _WORKSPACE,
        "task_id": _TASK,
        "yoetz_session_id": _FINISHUP_SESSION,
        "session_commitment": _SESSION,
        "source": "claude_hook",
        "source_identity": f"hook:consent-cleanup-{ticket_number}",
        "source_generation": 1,
        "byte_position": 0,
        "event_position": 1,
        "last_source_commitment": _SOURCE,
        "mapping_version": "claude-code-hooks-ordinary-v2",
        "logical_identity": "sha256:" + f"{ticket_number + 100:064x}",
        "content_capture_profile": profile,
        "authority_generation": "sha256:" + "b" * 64,
        "expected_parts_json": canonical_encode(()),
        "object_ids_json": canonical_encode(()),
        "captured_at": _TIME.wire,
        "state": state,
    }
    columns = tuple(values)
    placeholders = ",".join("?" for _ in columns)
    db.execute(
        f"INSERT INTO observation_capture_tickets({','.join(columns)}) VALUES({placeholders})",
        tuple(values[column] for column in columns),
    )


def _open_store(path: str) -> tuple[apsw.Connection, SqliteObservationStore]:
    db = apsw.Connection(path)
    initialize_bundle(db, {"task_id": _TASK, "owner_generation": "1"})
    store = SqliteObservationStore(db)
    store.grant_consent(
        _WORKSPACE,
        _TIME,
        content_capture_profiles=(
            CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        ),
    )
    return db, store


def test_disable_content_capture_persists_ticket_tombstone(tmp_path: Path) -> None:
    path = str(tmp_path / "bundle.sqlite3")
    db, store = _open_store(path)
    try:
        _ticket_row(
            db,
            profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            ticket_number=1,
        )
        _ticket_row(db, profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID, ticket_number=2)
        store.disable_content_capture(_WORKSPACE, CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID)
        # Regranting the arm must not resurrect the old handoff.
        store.grant_consent(
            _WORKSPACE,
            _TIME,
            content_capture_profiles=(
                CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
                CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
            ),
        )
    finally:
        db.close()

    reopened = apsw.Connection(path)
    try:
        assert reopened.execute(
            "SELECT content_capture_profile,state FROM observation_capture_tickets "
            "WHERE workspace_commitment=? ORDER BY content_capture_profile",
            (_WORKSPACE,),
        ).fetchall() == [
            (CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID, "revoked"),
            (CURSOR_ORDINARY_OBSERVATION_PROFILE_ID, "pending"),
        ]
    finally:
        reopened.close()


def test_revoke_persists_all_ticket_tombstones(tmp_path: Path) -> None:
    path = str(tmp_path / "bundle.sqlite3")
    db, store = _open_store(path)
    try:
        _ticket_row(
            db,
            profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            ticket_number=3,
        )
        _ticket_row(db, profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID, ticket_number=4)
        # Revoke is the all-profile fence, including tickets that would have
        # survived a single-profile disable.
        asyncio.run(store.revoke(ObservationRevokeCommand(_WORKSPACE)))
        store.grant_consent(
            _WORKSPACE,
            _TIME,
            content_capture_profiles=(
                CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
                CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
            ),
        )
    finally:
        db.close()

    reopened = apsw.Connection(path)
    try:
        assert reopened.execute(
            "SELECT state FROM observation_capture_tickets "
            "WHERE workspace_commitment=? ORDER BY ticket_id",
            (_WORKSPACE,),
        ).fetchall() == [("revoked",), ("revoked",)]
    finally:
        reopened.close()
