"""Task-scoped view of the local hook outbox (tb4n1 B4/C6, issue #1012).

A hook outbox row belongs to a task when its host session is the caller's own host session or
any other host session whose lifecycle mapping names the same FinishUP session (a delegated child
lane). Rows of other tasks sharing the workspace, and rows of unmapped host sessions (which
cannot reach any task ledger until mapped), are never counted.

The Stop hook's closure gate and the service's optional pre-check wait
(``check`` with ``await_observations``) share these helpers so both read the same rows.
"""

from __future__ import annotations

from pathlib import Path

from finishup.adapters.integrations.codex_lifecycle import load_mapping
from finishup.adapters.integrations.observation_local import (
    LocalObservationStore,
    ObservationOutboxRow,
    PendingRolloutItem,
)
from finishup.domain.observation import ObservationSource

__all__ = [
    "session_pending_row_identities",
    "task_pending_outbox_count",
    "task_pending_outbox_rows",
]


def task_pending_outbox_rows(
    store: LocalObservationStore,
    *,
    workspace_commitment: str,
    yoetz_session_id: str,
    codex_session_id: str | None = None,
    _state: Path | None = None,
) -> tuple[ObservationOutboxRow, ...]:
    """Return one workspace's pending outbox rows that can still change this task's facts.

    ``codex_session_id`` names the caller's own host session, counted without a mapping read;
    ``None`` counts only host sessions whose mapping names ``yoetz_session_id``.
    """

    same_task: dict[str, bool] = {}
    rows: list[ObservationOutboxRow] = []
    for row in store.list_pending_outbox_rows(workspace_commitment):
        host_session = row.codex_session_id
        if host_session not in same_task:
            if codex_session_id is not None and host_session == codex_session_id:
                same_task[host_session] = True
            else:
                other = load_mapping(host_session, _state=_state)
                same_task[host_session] = (
                    other is not None and other.yoetz_session_id == yoetz_session_id
                )
        if same_task[host_session]:
            rows.append(row)
    return tuple(rows)


def task_pending_outbox_count(
    store: LocalObservationStore,
    *,
    workspace_commitment: str,
    yoetz_session_id: str,
    codex_session_id: str | None = None,
    _state: Path | None = None,
) -> int:
    """Count one workspace's pending outbox rows that can still change this task's facts."""

    return len(
        task_pending_outbox_rows(
            store,
            workspace_commitment=workspace_commitment,
            yoetz_session_id=yoetz_session_id,
            codex_session_id=codex_session_id,
            _state=_state,
        )
    )


def _stream_input_identity(source_identity: str) -> str:
    """One rollout input's wait identity, the same while it is held and once it is an outbox row."""

    return f"stream-input:{source_identity}"


def session_pending_row_identities(
    store: LocalObservationStore,
    *,
    yoetz_session_id: str,
    _state: Path | None = None,
    now: float | None = None,
) -> frozenset[str]:
    """Return the opaque identities of every pending row mapped to one FinishUP session.

    Reads every workspace that still holds local delivery work; the identities are digests
    of the structural row, never its content, and are compared only inside the service.

    Rollout tool items still held for their hook post (#910) count too (tb4n5): the wait
    releases each one read long enough ago (``release_held_rollout_items_for_check``, delivered
    with ``unpaired_event``) so it lands before the check, and counts a younger one as still
    pending, under an identity that stays the same once it is released into the outbox.
    """

    from finishup.adapters.integrations.codex_session_stream import (
        release_held_rollout_items_for_check,
    )
    from finishup.adapters.integrations.observation_admission import build_routine_read_summary

    identities: set[str] = set()
    same_task: dict[str, bool] = {}

    def task_item(item: PendingRolloutItem) -> bool:
        host_session = item.codex_session_id
        if host_session not in same_task:
            mapping = load_mapping(host_session, _state=_state)
            same_task[host_session] = (
                mapping is not None and mapping.yoetz_session_id == yoetz_session_id
            )
        return same_task[host_session]

    for workspace in store.held_rollout_workspaces():
        identities.update(
            _stream_input_identity(source_identity)
            for source_identity in release_held_rollout_items_for_check(
                store, workspace, task_item, now=now
            )
        )
    for workspace in store.pending_workspaces():
        # Inputs still held in the admission buffer (routine reads and pending attempts, held
        # up to a few seconds for summarization) are not outbox rows yet. Flush this task's
        # host sessions now so the wait covers them instead of reporting `complete` early.
        for host_session in store.buffered_admission_host_sessions(workspace):
            mapping = load_mapping(host_session, _state=_state)
            if mapping is None or mapping.yoetz_session_id != yoetz_session_id:
                continue
            store.flush_selected_admission(
                workspace,
                summary_builder=build_routine_read_summary,
                force=True,
                host_session=host_session,
            )
        for row in task_pending_outbox_rows(
            store,
            workspace_commitment=workspace,
            yoetz_session_id=yoetz_session_id,
            _state=_state,
        ):
            identities.add(
                _stream_input_identity(row.envelope.source_identity)
                if row.envelope.source is ObservationSource.CODEX_SESSION_STREAM
                else row.row_identity
            )
    return frozenset(identities)
