"""Issue #1012: the task-scoped view of the local hook outbox shared by Stop and check."""

from __future__ import annotations

from pathlib import Path

from yoetz.adapters.integrations.codex_lifecycle import mapping_from_start_ids, store_mapping
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.adapters.integrations.observation_task_pending import (
    session_pending_row_identities,
    task_pending_outbox_count,
)
from yoetz.cli import observe_hooks as observe_hooks_module
from yoetz.cli.observe_hooks import map_hook_payload_to_envelope
from yoetz.domain.observation import ObservationSource
from yoetz.protocol.ids import IdKind, new_id


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


def _map(state: Path, host_session: str, yoetz_session: str) -> None:
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=host_session,
            yoetz_task_id=new_id(IdKind.TASK),
            yoetz_session_id=yoetz_session,
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
