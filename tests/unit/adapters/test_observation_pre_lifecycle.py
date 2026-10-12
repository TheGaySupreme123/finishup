from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.domain.observation import ObservationSource, ObservationStatusQuery
from yoetz.domain.values import Timestamp

_NOW = Timestamp("2026-09-10T00:01:00.000Z")
_WALL_SECONDS = datetime(2026, 9, 10, 0, 1, tzinfo=UTC).timestamp()
_SESSION = "hmac-sha256:" + "1" * 64


def _store(tmp_path: Path, wall: list[float]) -> tuple[LocalObservationStore, str]:
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir()
    store = LocalObservationStore(
        _state=tmp_path / "state",
        _monotonic=lambda: 0.0,
        _wall=lambda: wall[0],
    )
    return store, store.workspace_commitment(str(workspace_path))


def test_open_pre_roundtrip_preserves_scope_and_original_deadline(tmp_path: Path) -> None:
    wall = [_WALL_SECONDS]
    store, workspace = _store(tmp_path, wall)
    receipt = Timestamp("2026-09-10T00:00:30.000Z")
    assert store.note_open_pre(
        workspace,
        "call-roundtrip",
        "PreToolUse",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=_SESSION,
        source_generation=7,
        receipt_time=receipt,
    )

    payload = cast(Mapping[str, object], json.loads(store._workspace_path(workspace).read_text()))  # pyright: ignore[reportPrivateUsage]
    open_pre = cast(Mapping[str, object], payload["open_pre"])
    entry = cast(Mapping[str, object], next(iter(open_pre.values())))
    assert entry["event_kind"] == "PreToolUse"
    assert entry["source"] == ObservationSource.CODEX_HOOK.value
    assert entry["session_commitment"] == _SESSION
    assert entry["source_generation"] == 7
    assert entry["correlation_id"] == "call-roundtrip"
    assert entry["receipt_time"] == receipt.wire
    assert entry["deadline"] == "2026-09-10T00:10:30.000Z"

    reopened = LocalObservationStore(_state=tmp_path / "state", _wall=lambda: wall[0])
    with reopened._lock:  # pyright: ignore[reportPrivateUsage]
        state = reopened._load(workspace)  # pyright: ignore[reportPrivateUsage]
        assert state.open_pre is not None
        loaded = next(iter(state.open_pre.values()))
        assert loaded.source is ObservationSource.CODEX_HOOK
        assert loaded.session_commitment == _SESSION
        assert loaded.source_generation == 7
        assert loaded.receipt_time == receipt
        assert loaded.deadline == Timestamp("2026-09-10T00:10:30.000Z")

    # A retry with a new receipt cannot keep a missing post alive forever.
    wall[0] += 20
    assert reopened.note_open_pre(
        workspace,
        "call-roundtrip",
        "PreToolUse",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=_SESSION,
        source_generation=7,
        receipt_time=_NOW,
    )
    with reopened._lock:  # pyright: ignore[reportPrivateUsage]
        state = reopened._load(workspace)  # pyright: ignore[reportPrivateUsage]
        assert state.open_pre is not None
        loaded = next(iter(state.open_pre.values()))
        assert loaded.receipt_time == receipt
        assert loaded.deadline == Timestamp("2026-09-10T00:10:30.000Z")


def test_missing_post_expires_across_restart_with_explicit_gap(tmp_path: Path) -> None:
    wall = [_WALL_SECONDS]
    store, workspace = _store(tmp_path, wall)
    assert store.note_open_pre(
        workspace,
        "call-missing-post",
        "PreToolUse",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=_SESSION,
        source_generation=1,
        receipt_time=_NOW,
    )

    wall[0] += 120
    # Execution time beyond the delivery-age pressure horizon does not
    # itself mean that the host lost the post event.
    assert store.has_open_pre(
        workspace,
        "call-missing-post",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=_SESSION,
        source_generation=1,
    )
    wall[0] += 480.001
    reopened = LocalObservationStore(_state=tmp_path / "state", _wall=lambda: wall[0])
    evaluation = reopened.update_selection_pressure(workspace, _SESSION)
    assert evaluation.admission_allowed
    status = reopened.selection_runtime_status(workspace, _SESSION)
    assert status["pending_attempts"] == 0
    assert "pending_attempt_expired" in reopened.status(ObservationStatusQuery(workspace)).gaps


def test_session_end_clears_only_ended_generation_open_pre(tmp_path: Path) -> None:
    wall = [_WALL_SECONDS]
    store, workspace = _store(tmp_path, wall)
    generation = store.begin_session_generation(workspace, _SESSION)
    assert generation == 1
    assert store.note_open_pre(
        workspace,
        "call-ended",
        "PreToolUse",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=_SESSION,
        source_generation=generation,
        receipt_time=_NOW,
    )
    store.note_session_end(workspace, _SESSION, generation=generation)
    assert store.selection_runtime_status(workspace, _SESSION)["pending_attempts"] == 0

    assert store.begin_session_generation(workspace, _SESSION) == 2
    assert store.note_open_pre(
        workspace,
        "call-new-generation",
        "PreToolUse",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=_SESSION,
        source_generation=2,
        receipt_time=_NOW,
    )
    # A delayed end from generation one cannot clear generation two's pre.
    store.note_session_end(workspace, _SESSION, generation=1)
    assert store.selection_runtime_status(workspace, _SESSION)["pending_attempts"] == 1


def test_a_file_change_naming_another_open_call_closes_no_pre_only_attempt(
    tmp_path: Path,
) -> None:
    """#1041: only an unattributable item id falls back to the oldest pre-only attempt."""

    wall = [_WALL_SECONDS]
    store, workspace = _store(tmp_path, wall)
    for call, pre_only in (("call_shell_patch", True), ("call_native_patch", False)):
        assert store.note_open_pre(
            workspace,
            call,
            "PreToolUse",
            source=ObservationSource.CODEX_HOOK,
            session_commitment=_SESSION,
            source_generation=1,
            receipt_time=_NOW,
            pre_only=pre_only,
        )
    # A direct call's own change names that call: the shell patch stays pending.
    assert not store.close_pre_only_attempt(workspace, _SESSION, "call_native_patch")
    assert store.selection_runtime_status(workspace, _SESSION)["pending_attempts"] == 2
    # Code mode's ``exec-<uuid>`` names no hook call: the oldest pre-only attempt closes.
    assert store.close_pre_only_attempt(workspace, _SESSION, "exec-0e5dcfc8-patch")
    assert store.selection_runtime_status(workspace, _SESSION)["pending_attempts"] == 1
    assert store.has_open_pre(
        workspace,
        "call_native_patch",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=_SESSION,
        source_generation=1,
    )
