"""Issue #1012: the task-scoped view of the local hook outbox shared by Stop and check."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from finishup.adapters.integrations.codex_lifecycle import mapping_from_start_ids, store_mapping
from finishup.adapters.integrations.observation_local import (
    STREAM_MAPPING_VERSION,
    LocalObservationStore,
)
from finishup.adapters.integrations.observation_task_pending import (
    session_pending_row_identities,
    task_pending_outbox_count,
)
from finishup.cli import observe_hooks as observe_hooks_module
from finishup.cli.observe_hooks import map_hook_payload_to_envelope
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationSource,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.ids import IdKind, new_id


def _enqueue(store: LocalObservationStore, workspace: str, session: str, ordinal: int) -> None:
    store.bind_codex_session(workspace, session)
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "session_id": session,
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": f"call-{session}-{ordinal}",
            "exit_status": 0,
        },
        session_commitment=store.session_commitment(session),
        event_ordinal=ordinal,
        key_material=store.key_material(),
        source=ObservationSource.CODEX_HOOK,
    )
    store.enqueue_outbox(workspace, session, envelope)


def _map(state: Path, host_session: str, finishup_session: str) -> None:
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=host_session,
            yoetz_task_id=new_id(IdKind.TASK),
            yoetz_session_id=finishup_session,
            yoetz_writer_id=new_id(IdKind.WRITER),
            last_frontier="0:genesis",
        ),
        _state=state,
    )


def _workspace(store: LocalObservationStore, path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    workspace = store.workspace_commitment(str(path.resolve()))
    store.grant_consent(workspace)
    return workspace


def test_session_rows_span_workspaces_and_skip_other_tasks_and_unmapped(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    mine = new_id(IdKind.SESSION)
    other = new_id(IdKind.SESSION)
    first = _workspace(store, tmp_path / "repo-a")
    second = _workspace(store, tmp_path / "repo-b")
    _map(tmp_path, "codex:parent", mine)
    _map(tmp_path, "codex:child", mine)
    _map(tmp_path, "codex:foreign", other)
    _enqueue(store, first, "codex:parent", 1)
    _enqueue(store, first, "codex:parent", 2)
    _enqueue(store, second, "codex:child", 1)
    _enqueue(store, first, "codex:foreign", 1)
    _enqueue(store, first, "codex:unmapped", 1)

    identities = session_pending_row_identities(store, yoetz_session_id=mine, _state=tmp_path)

    expected = {
        row.row_identity
        for workspace in (first, second)
        for row in store.list_pending_outbox_rows(workspace)
        if row.codex_session_id in {"codex:parent", "codex:child"}
    }
    assert identities == expected
    assert len(identities) == 3
    assert session_pending_row_identities(store, yoetz_session_id=other, _state=tmp_path) == {
        row.row_identity
        for row in store.list_pending_outbox_rows(first)
        if row.codex_session_id == "codex:foreign"
    }

    # Delivering a row removes it from the next read of real state.
    delivered = store.list_pending_outbox_rows(second)[0]
    assert store.acknowledge_outbox_row(second, delivered) is True
    after = session_pending_row_identities(store, yoetz_session_id=mine, _state=tmp_path)
    assert after == expected - {delivered.row_identity}


def test_stop_wrapper_keeps_its_counting_rule(tmp_path: Path) -> None:
    """The Stop gate's helper still counts its own unmapped host session (B4/C6)."""

    store = LocalObservationStore(_state=tmp_path)
    mine = new_id(IdKind.SESSION)
    workspace = _workspace(store, tmp_path / "repo")
    _map(tmp_path, "codex:child", mine)
    _enqueue(store, workspace, "codex:self", 1)
    _enqueue(store, workspace, "codex:child", 1)
    _enqueue(store, workspace, "codex:stranger", 1)

    count = observe_hooks_module._task_pending_outbox_count(  # pyright: ignore[reportPrivateUsage]
        store,
        workspace_commitment=workspace,
        codex_session_id="codex:self",
        yoetz_session_id=mine,
        _state=tmp_path,
    )

    assert count == 2
    assert (
        task_pending_outbox_count(
            store,
            workspace_commitment=workspace,
            yoetz_session_id=mine,
            codex_session_id="codex:self",
            _state=tmp_path,
        )
        == 2
    )
    # Without a host session of its own (the service-side wait) only mapped rows count.
    assert (
        task_pending_outbox_count(
            store, workspace_commitment=workspace, yoetz_session_id=mine, _state=tmp_path
        )
        == 1
    )


def test_buffered_inputs_of_this_task_are_flushed_into_the_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review of #1012: routine reads held in the admission buffer must not read as delivered."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = _workspace(store, tmp_path / "w")
    mine = new_id(IdKind.SESSION)
    _map(tmp_path, "mine", mine)
    _map(tmp_path, "theirs", new_id(IdKind.SESSION))
    _enqueue(store, workspace, "theirs", 1)  # keeps the workspace in pending_workspaces
    flushed: list[str | None] = []

    def buffered(_workspace: str) -> tuple[str, ...]:
        return ("mine", "theirs")

    def flush(_workspace: str, **kwargs: object) -> bool:
        flushed.append(kwargs.get("host_session"))  # type: ignore[arg-type]
        assert kwargs.get("force") is True
        _enqueue(store, workspace, "mine", 7)
        return True

    monkeypatch.setattr(store, "buffered_admission_host_sessions", buffered)
    monkeypatch.setattr(store, "flush_selected_admission", flush)
    identities = session_pending_row_identities(store, yoetz_session_id=mine, _state=tmp_path)
    assert flushed == ["mine"]
    assert len(identities) == 1


def _held_item(
    store: LocalObservationStore, workspace: str, host_session: str, call: str, read_at: str
) -> str:
    """Hold one rollout command item for its hook post, read at ``read_at`` (#910)."""

    session = store.bind_codex_session(workspace, host_session)
    envelope = ObservationEnvelope(
        session_commitment=session,
        event_kind="item_completed",
        source_identity=f"stream:{call}",
        source=ObservationSource.CODEX_SESSION_STREAM,
        cursor=ObservationCursor(1, 120, 4, f"hmac-sha256:{'cd' * 32}", STREAM_MAPPING_VERSION),
        receipt_time=Timestamp(read_at),
        structural_payload=JsonObject(
            {
                "action": "CommandExecution",
                "exit_status": 0,
                "stream_kind": "event_msg",
                "tool_call_id": call,
                "tool_name": "command_execution",
            }
        ),
        content_object_refs=(),
        gap_codes=(),
    )
    store.note_pending_rollout_item(workspace, session, host_session, envelope)
    return envelope.source_identity


def test_held_rollout_items_of_this_task_are_released_into_the_wait(tmp_path: Path) -> None:
    """tb4n5 biped S: a held item landed 13 minutes late, 3 s after the check that awaited.

    The wait releases each of its task's held items read long enough ago, with
    ``unpaired_event``, and counts a younger one as still pending under an identity that does not
    change once it is released. Another task's held item is left alone.
    """

    store = LocalObservationStore(_state=tmp_path)
    workspace = _workspace(store, tmp_path / "w")
    mine = new_id(IdKind.SESSION)
    _map(tmp_path, "mine", mine)
    _map(tmp_path, "theirs", new_id(IdKind.SESSION))
    old = _held_item(store, workspace, "mine", "exec-old", "2026-10-12T19:43:07.246Z")
    young = _held_item(store, workspace, "mine", "exec-young", "2026-10-12T19:56:00.000Z")
    foreign = _held_item(store, workspace, "theirs", "exec-foreign", "2026-10-12T19:40:00.000Z")
    check_at = datetime(2026, 10, 12, 19, 56, 2, tzinfo=UTC).timestamp()

    identities = session_pending_row_identities(
        store, yoetz_session_id=mine, _state=tmp_path, now=check_at
    )

    assert identities == {f"stream-input:{old}", f"stream-input:{young}"}
    (released,) = store.list_pending_outbox_rows(workspace)
    assert released.envelope.source_identity == old
    assert ObservationGapCode.UNPAIRED_EVENT.value in released.envelope.gap_codes
    held = {item.source_identity for item in store.pending_rollout_items(workspace)}
    assert held == {young, foreign}

    # Once delivered it leaves the wait; the young item is the bounded remainder.
    assert store.acknowledge_outbox_row(workspace, released) is True
    after = session_pending_row_identities(
        store, yoetz_session_id=mine, _state=tmp_path, now=check_at
    )
    assert after == {f"stream-input:{young}"}
