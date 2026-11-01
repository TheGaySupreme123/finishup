"""Upgrade-safe bootstrap fencing for workspace capture reservations."""

from __future__ import annotations

from pathlib import Path

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.domain.observation import ObservationCaptureBacklog
from finishup.domain.values import Timestamp

_OLDEST = Timestamp("2026-09-10T00:00:00.000Z")
_OBSERVED = Timestamp("2026-09-10T00:00:05.000Z")


def _workspace(store: LocalObservationStore, root: Path) -> str:
    return store.workspace_commitment(str(root.resolve()))


def test_legacy_or_partial_state_cannot_claim_a_bootstrap_root(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = _workspace(store, tmp_path)

    store.update_capture_backlog(
        workspace,
        2,
        700,
        _OLDEST,
        _OBSERVED,
        route_id="tsk_known",
    )

    assert store.capture_reservation_bootstrap_ready(workspace) is False


def test_complete_bootstrap_round_trips_and_recovers_sticky_unknown(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = _workspace(store, tmp_path)
    backlog = ObservationCaptureBacklog(2, 700, _OLDEST)

    store.mark_capture_backlog_scope_unknown(workspace)
    store.bootstrap_capture_reservations(
        workspace,
        {"tsk_known": backlog},
        observed_at=_OBSERVED,
        complete=True,
    )

    assert store.capture_reservation_bootstrap_ready(workspace, "tsk_known") is True
    # The public pressure scope remains partial; the internal root proof is
    # what authorizes a new central reservation.
    snapshot = store.capture_backlog(workspace)
    assert snapshot["capture_backlog_scope"] == "partial"
    assert snapshot["count"] == 2
    assert snapshot["byte_count"] == 700

    reopened = LocalObservationStore(_state=tmp_path)
    assert reopened.capture_reservation_bootstrap_ready(workspace, "tsk_known") is True
    assert reopened.capture_backlog(workspace) == snapshot


def test_partial_route_update_does_not_clear_unknown_until_complete_rebootstrap(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = _workspace(store, tmp_path)
    store.mark_capture_backlog_scope_unknown(workspace)

    store.update_capture_backlog(
        workspace,
        0,
        0,
        None,
        _OBSERVED,
        route_id="tsk_known",
    )
    assert store.capture_reservation_bootstrap_ready(workspace) is False

    store.bootstrap_capture_reservations(
        workspace,
        {"tsk_known": ObservationCaptureBacklog(0, 0, None)},
        observed_at=_OBSERVED,
        complete=True,
    )
    assert store.capture_reservation_bootstrap_ready(workspace, "tsk_known") is True


def test_new_route_invalidates_the_previous_root_proof(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = _workspace(store, tmp_path)
    store.bootstrap_capture_reservations(
        workspace,
        {"tsk_first": ObservationCaptureBacklog(0, 0, None)},
        observed_at=_OBSERVED,
        complete=True,
    )
    assert store.capture_reservation_bootstrap_ready(workspace, "tsk_first") is True

    store.update_capture_backlog(
        workspace,
        1,
        5,
        _OLDEST,
        _OBSERVED,
        route_id="tsk_second",
    )
    assert store.capture_reservation_bootstrap_ready(workspace) is False
    assert store.capture_backlog(workspace)["capture_backlog_scope"] == "unknown"


def test_unknown_inventory_is_durable_maintenance_work_with_an_empty_outbox(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = _workspace(store, tmp_path)
    store.bootstrap_capture_reservations(
        workspace, {"tsk_first": ObservationCaptureBacklog(0, 0, None)}
    )
    assert store.pending_workspaces() == ()
    store.update_capture_backlog(workspace, 0, 0, None, _OBSERVED, route_id="tsk_second")
    assert store.pending_outbox_count(workspace) == 0
    assert store.pending_workspaces() == (workspace,)
    reopened = LocalObservationStore(_state=tmp_path)
    assert reopened.pending_workspaces() == (workspace,)
    assert reopened.capture_inventory_recovery_needed(workspace)
    reopened.bootstrap_capture_reservations(
        workspace,
        {
            "tsk_first": ObservationCaptureBacklog(0, 0, None),
            "tsk_second": ObservationCaptureBacklog(0, 0, None),
        },
    )
    assert not reopened.capture_inventory_recovery_needed(workspace)
    assert reopened.pending_workspaces() == ()
