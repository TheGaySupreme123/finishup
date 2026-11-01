"""Bounded explicit read protection remains fenced and retry-safe."""

from __future__ import annotations

from pathlib import Path

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.domain.observation import (
    ObservationControlCommand,
    ObservationCursor,
    ObservationEnvelope,
    ObservationRevokeCommand,
    ObservationSource,
)
from finishup.domain.observation_read_protection import (
    MAX_READ_PROTECTION_COUNT,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.errors import ProtocolValueError

_REFERENCE = "clm_00000000-0000-4000-8000-000000000001"
_REFERENCE_TWO = "fnd_00000000-0000-4000-8000-000000000002"
_STAMP = Timestamp("2026-01-01T00:00:00.000Z")


def _store(tmp_path: Path) -> tuple[LocalObservationStore, str, str]:
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state, _wall=lambda: _STAMP.as_datetime().timestamp())
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace, _STAMP)
    session = store.bind_codex_session(workspace, "read-protection-session")
    return store, workspace, session


def _envelope(
    session: str,
    *,
    event_kind: str,
    call_id: str = "call-read-1",
    generation: int = 1,
    tool_name: str = "Read",
    action: str | None = None,
) -> ObservationEnvelope:
    structural = {"tool_name": tool_name, "tool_call_id": call_id}
    if action is not None:
        structural["action"] = action
    return ObservationEnvelope(
        session_commitment=session,
        event_kind=event_kind,
        source_identity=f"hook:{event_kind}:{call_id}",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(
            generation,
            0,
            1 if event_kind == "PreToolUse" else 2,
            "hmac-sha256:" + "1" * 64,
            "codex-obs-hook/1.0.0",
        ),
        receipt_time=_STAMP,
        structural_payload=JsonObject(structural),
        content_object_refs=(),
        gap_codes=(),
    )


def test_protection_preserves_pre_post_and_exact_post_retry(tmp_path: Path) -> None:
    store, workspace, session = _store(tmp_path)
    result = store.protect_next_reads(workspace, session, _REFERENCE)

    assert result["protected"] is True
    assert result["count"] == 1
    assert result["expires_at"] == "2026-01-01T00:10:00.000Z"
    pre = _envelope(session, event_kind="PreToolUse")
    post = _envelope(session, event_kind="PostToolUse")

    assert store.read_is_protected(workspace, session, pre)
    assert not store.consume_read_protection(workspace, session, pre)
    assert store.read_is_protected(workspace, session, post)
    assert store.consume_read_protection(workspace, session, post)
    assert not store.consume_read_protection(workspace, session, post)
    # A replay of the exact post remains linked to its protected identity;
    # consume is the idempotent no-op that prevents a second decrement.
    assert store.read_is_protected(workspace, session, post)


def test_protection_round_trips_but_session_generation_fences_it(tmp_path: Path) -> None:
    store, workspace, session = _store(tmp_path)
    store.protect_next_reads(workspace, session, _REFERENCE)
    reopened = LocalObservationStore(
        _state=tmp_path / "state", _wall=lambda: _STAMP.as_datetime().timestamp()
    )
    assert reopened.read_is_protected(
        workspace, session, _envelope(session, event_kind="PreToolUse")
    )

    reopened.begin_session_generation(workspace, session)
    assert not reopened.read_is_protected(
        workspace,
        session,
        _envelope(session, event_kind="PreToolUse", generation=2),
    )


def test_pre_reservations_keep_out_of_order_posts_on_their_own_scope(tmp_path: Path) -> None:
    store, workspace, session = _store(tmp_path)
    store.protect_next_reads(workspace, session, _REFERENCE)
    store.protect_next_reads(workspace, session, _REFERENCE_TWO)
    pre_a = _envelope(session, event_kind="PreToolUse", call_id="call-a")
    pre_b = _envelope(session, event_kind="PreToolUse", call_id="call-b")
    post_a = _envelope(session, event_kind="PostToolUse", call_id="call-a")
    post_b = _envelope(session, event_kind="PostToolUse", call_id="call-b")

    assert store.read_is_protected(workspace, session, pre_a)
    assert store.read_is_protected(workspace, session, pre_b)
    assert store.read_protection_reference(workspace, session, post_b) == _REFERENCE_TWO
    assert store.consume_read_protection(workspace, session, post_b)
    assert store.read_protection_reference(workspace, session, post_a) == _REFERENCE
    assert store.consume_read_protection(workspace, session, post_a)


def test_extending_reference_scope_preserves_reserved_pre_identity(tmp_path: Path) -> None:
    store, workspace, session = _store(tmp_path)
    store.protect_next_reads(workspace, session, _REFERENCE, count=2)
    pre = _envelope(session, event_kind="PreToolUse", call_id="reserved-call")
    assert store.read_is_protected(workspace, session, pre)

    # Extending an existing scope must retain the reservation for the first
    # logical call while adding one fresh slot for a later call.
    store.protect_next_reads(workspace, session, _REFERENCE, count=1)
    post = _envelope(session, event_kind="PostToolUse", call_id="reserved-call")
    later = _envelope(session, event_kind="PreToolUse", call_id="later-call")
    assert store.read_protection_reference(workspace, session, post) == _REFERENCE
    assert store.consume_read_protection(workspace, session, post)
    assert store.read_is_protected(workspace, session, later)


def test_unfinished_pre_scope_is_dropped_at_expiry(tmp_path: Path) -> None:
    clock = [_STAMP.as_datetime().timestamp()]
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state, _wall=lambda: clock[0])
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace, _STAMP)
    session = store.bind_codex_session(workspace, "lost-post-session")
    store.protect_next_reads(
        workspace,
        session,
        _REFERENCE,
        expires_at=Timestamp("2026-01-01T00:00:01.000Z"),
    )
    pre = _envelope(session, event_kind="PreToolUse")
    assert store.read_is_protected(workspace, session, pre)
    clock[0] += 2
    assert not store.read_is_protected(workspace, session, pre)


def test_pause_resume_does_not_reactivate_old_scope(tmp_path: Path) -> None:
    store, workspace, session = _store(tmp_path)
    store.protect_next_reads(workspace, session, _REFERENCE)
    store.pause(ObservationControlCommand(workspace))
    store.resume(ObservationControlCommand(workspace))

    assert not store.read_is_protected(
        workspace, session, _envelope(session, event_kind="PreToolUse")
    )


def test_repeated_structural_grant_keeps_an_active_scope(tmp_path: Path) -> None:
    """Issue #835: routine setup (another host's connection) is not a consent transition."""

    store, workspace, session = _store(tmp_path)
    store.protect_next_reads(workspace, session, _REFERENCE)

    store.grant_consent(workspace)

    assert store.read_is_protected(workspace, session, _envelope(session, event_kind="PreToolUse"))


def test_revoke_and_fresh_grant_do_not_reactivate_old_scope(tmp_path: Path) -> None:
    store, workspace, session = _store(tmp_path)
    store.protect_next_reads(workspace, session, _REFERENCE)
    store.revoke(ObservationRevokeCommand(workspace))
    pending = store.pending_consent_revocation(workspace)
    assert pending is not None
    store.mark_consent_revocation_fenced(workspace, pending[0])

    store.grant_consent(workspace)

    assert not store.read_is_protected(
        workspace, session, _envelope(session, event_kind="PreToolUse")
    )


def test_expiry_is_bounded_and_expires_without_a_hook_side_channel(tmp_path: Path) -> None:
    clock = [_STAMP.as_datetime().timestamp()]
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state, _wall=lambda: clock[0])
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace, _STAMP)
    session = store.bind_codex_session(workspace, "expiry-session")
    expiry = Timestamp("2026-01-01T00:00:01.000Z")
    store.protect_next_reads(workspace, session, _REFERENCE, expires_at=expiry)
    clock[0] += 2

    assert not store.read_is_protected(
        workspace, session, _envelope(session, event_kind="PreToolUse")
    )
    with pytest.raises(ProtocolValueError):
        store.protect_next_reads(
            workspace,
            session,
            _REFERENCE,
            expires_at=Timestamp("2026-01-01T00:20:00.000Z"),
        )


def test_only_closed_read_structure_matches_and_reference_labels_do_not(tmp_path: Path) -> None:
    store, workspace, session = _store(tmp_path)
    store.protect_next_reads(workspace, session, _REFERENCE)
    forged = _envelope(
        session,
        event_kind="PreToolUse",
        tool_name="unknown_tool",
        action="routine_read",
    )
    assert not store.read_is_protected(workspace, session, forged)


@pytest.mark.parametrize("count", [0, MAX_READ_PROTECTION_COUNT + 1])
def test_count_is_bounded(tmp_path: Path, count: int) -> None:
    store, workspace, session = _store(tmp_path)
    with pytest.raises(ProtocolValueError):
        store.protect_next_reads(workspace, session, _REFERENCE, count=count)
