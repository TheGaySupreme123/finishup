"""Adversarial regressions for the multi-session observation lanes (#498)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

import finishup.adapters.integrations.observation_local as local_mod
from finishup.adapters.integrations.codex_lifecycle import acquire_session_lock
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_verification import (
    ObservationVerificationSupervisor,
    VerificationDrainHandle,
)
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationIngestDisposition,
    ObservationSource,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.errors import PublicErrorCode, PublicOperationError


def _envelope(*, session: str, identity: str, ordinal: int = 1) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=session,
        event_kind="PreToolUse",
        source_identity=identity,
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(
            1,
            0,
            ordinal,
            "hmac-sha256:" + "ab" * 32,
            "codex-obs-hook/1.0.0",
        ),
        receipt_time=Timestamp("2026-01-01T00:00:00.000Z"),
        structural_payload=JsonObject({"tool_name": "shell", "tool_call_id": f"call-{identity}"}),
        content_object_refs=(),
        gap_codes=(),
    )


def test_duplicate_replay_is_admitted_when_its_lane_is_at_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A retry of an existing full-lane row must not create a false overflow gap."""

    monkeypatch.setattr(local_mod, "_MAX_OUTBOX", 3)
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "session-busy")
    envelopes = tuple(
        _envelope(session=session, identity=f"busy:{ordinal}", ordinal=ordinal)
        for ordinal in range(1, 4)
    )

    for envelope in envelopes:
        assert store.enqueue_outbox(workspace, "session-busy", envelope) is None

    assert store.enqueue_outbox(workspace, "session-busy", envelopes[0]) is None
    assert store.session_gap_codes(workspace, session) == ()
    assert [
        row.envelope.source_identity
        for row in store.list_pending_outbox_rows(workspace, codex_session_id="session-busy")
    ] == ["busy:1", "busy:2", "busy:3"]


def test_raw_session_cannot_be_bound_to_two_workspaces(tmp_path: Path) -> None:
    """The same host session must have one durable workspace owner."""

    store = LocalObservationStore(_state=tmp_path)
    first_workspace = store.workspace_commitment(str(tmp_path / "workspace-a"))
    second_workspace = store.workspace_commitment(str(tmp_path / "workspace-b"))
    store.grant_consent(first_workspace)
    store.grant_consent(second_workspace)

    store.bind_codex_session(first_workspace, "session-shared")
    with pytest.raises(PublicOperationError) as raised:
        store.bind_codex_session(second_workspace, "session-shared")

    assert raised.value.code is PublicErrorCode.SESSION_CONFLICT


def test_explicit_fallback_owner_blocks_raw_session_rebinding(tmp_path: Path) -> None:
    """A fallback envelope route is also durable ownership evidence."""

    store = LocalObservationStore(_state=tmp_path)
    first_workspace = store.workspace_commitment(str(tmp_path / "workspace-a"))
    second_workspace = store.workspace_commitment(str(tmp_path / "workspace-b"))
    store.grant_consent(first_workspace)
    store.grant_consent(second_workspace)
    session = store.session_commitment("session-shared")

    assert (
        store.ingest(
            _envelope(session=session, identity="fallback:1"),
            workspace_commitment=first_workspace,
        ).disposition
        is ObservationIngestDisposition.ACCEPTED
    )
    with pytest.raises(PublicOperationError) as raised:
        store.bind_codex_session(second_workspace, "session-shared")

    assert raised.value.code is PublicErrorCode.SESSION_CONFLICT


@dataclass
class _Worker:
    service_generation: int = 1
    calls: int = 0
    fail: bool = False

    async def run_once(self) -> object | None:
        self.calls += 1
        if self.fail:
            raise RuntimeError("lane failed")
        return object() if self.calls == 1 else None


@pytest.mark.anyio
async def test_one_failed_verification_lane_does_not_stop_sibling_lanes() -> None:
    """A lane error must remain isolated while an unrelated lane keeps draining."""

    workspace = "hmac-sha256:" + "a" * 64
    supervisor = ObservationVerificationSupervisor(service_generation=1)
    failed = _Worker(fail=True)
    sibling = _Worker()
    supervisor.register(
        VerificationDrainHandle(
            workspace_commitment=workspace,
            worker=failed,  # type: ignore[arg-type]
            task_id="failed-task",
        )
    )
    supervisor.register(
        VerificationDrainHandle(
            workspace_commitment=workspace,
            worker=sibling,  # type: ignore[arg-type]
            task_id="sibling-task",
        )
    )

    assert await supervisor._drain_once() is True  # pyright: ignore[reportPrivateUsage]
    assert sibling.calls == 1
    assert await supervisor._drain_once() is False  # pyright: ignore[reportPrivateUsage]
    assert sibling.calls == 2


def test_busy_lifecycle_lane_does_not_strand_an_unrelated_pending_lane(tmp_path: Path) -> None:
    """A pending session lock must not prevent another session's intent from converging."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    for session_id in ("session-a", "session-b"):
        assert store.record_pending_session_lifecycle(
            workspace,
            session_id,
            store.session_commitment(session_id),
            "SessionStart",
            1,
        )

    with acquire_session_lock("session-a", _state=tmp_path) as owned:
        assert owned
        assert store.reconcile_pending_session_lifecycles(workspace) is True

    assert store.list_pending_session_lifecycles(workspace, "session-a")
    assert store.list_pending_session_lifecycles(workspace, "session-b") == ()


def test_evicted_active_hook_counter_keeps_a_workspace_high_water_mark(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Evicting an active session's cache entry must not reuse its ordinal."""

    monkeypatch.setattr(local_mod, "_MAX_HOOK_SEQUENCES", 2)
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    sessions = tuple(
        store.bind_codex_session(workspace, session_id)
        for session_id in ("session-a", "session-b", "session-c")
    )

    assert store.allocate_hook_ordinal(workspace, sessions[0]) == 1
    assert store.allocate_hook_ordinal(workspace, sessions[1]) == 2
    # C overflows the two-entry cache and evicts the oldest active lane A.
    assert store.allocate_hook_ordinal(workspace, sessions[2]) == 3
    reloaded = LocalObservationStore(_state=tmp_path)
    assert reloaded.allocate_hook_ordinal(workspace, sessions[0]) == 4
    # A is re-touched, so B is now the oldest active entry and can be evicted.
    assert reloaded.allocate_hook_ordinal(workspace, sessions[1]) == 5


def test_pruning_removes_inactive_membership_state_but_preserves_replay_state(
    tmp_path: Path,
) -> None:
    """Binding GC must remove lifecycle roots without resetting a resumed session."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session_id = "session-pruned"
    session = store.bind_codex_session(workspace, session_id)
    assert store.begin_session_generation(workspace, session) == 1
    store.note_session_end(workspace, session)
    assert store.allocate_hook_ordinal(workspace, session) == 1

    cursor = ObservationCursor(
        1,
        7,
        1,
        "hmac-sha256:" + "ab" * 32,
        "codex-obs-stream/1.3.0",
    )
    store.set_stream_reconcile_state(
        workspace,
        session,
        cursor=cursor,
        partial=b"",
        call_tools={},
        source_identity=None,
        profile_id=None,
    )

    assert store.prune_codex_session_bindings(workspace, (session_id,)) == (session_id,)
    state = store._load(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert state.session_workspaces is not None
    assert state.ended_sessions is not None
    assert state.ended_session_generations is not None
    assert state.session_generations is not None
    assert state.stream_cursors is not None
    assert state.hook_sequences is not None
    assert session not in state.session_workspaces
    assert session in state.ended_sessions
    assert session in state.ended_session_generations
    assert state.session_generations[session] == 1
    assert state.stream_cursors[session] == cursor
    assert state.hook_sequences[session] == 1

    assert store.bind_codex_session(workspace, session_id) == session
    assert store.begin_session_generation(workspace, session) == 2
    assert store.allocate_hook_ordinal(workspace, session) == 2


def test_pruning_bounds_session_replay_maps_and_keeps_live_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ended-session tombstones and replay indexes cannot grow with host history."""

    monkeypatch.setattr(local_mod, "_MAX_SESSION_REPLAY_KEYS", 2)
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    live = store.bind_codex_session(workspace, "session-live")

    for index in range(4):
        raw_session = f"session-ended-{index}"
        ended = store.bind_codex_session(workspace, raw_session)
        store.begin_session_generation(workspace, ended)
        store.note_session_end(workspace, ended)
        store.set_stream_cursor(
            workspace,
            ended,
            ObservationCursor(
                1,
                index,
                1,
                "hmac-sha256:" + "ab" * 32,
                "codex-obs-stream/1.3.0",
            ),
        )
        store.prune_codex_session_bindings(workspace, (raw_session,))

    state = store._load(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert state.session_generations is not None
    assert state.ended_session_generations is not None
    assert state.ended_sessions is not None
    assert state.stream_cursors is not None
    assert live not in state.ended_sessions
    assert len(state.session_generations) <= 2
    assert len(state.ended_session_generations) <= 2
    assert len(state.ended_sessions) <= 2
    assert len(state.stream_cursors) <= 2
