"""Bounded local capture-backlog feedback for pressure control."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

import finishup.adapters.integrations.observation_local as local_mod
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.domain.values import Timestamp
from finishup.protocol.errors import ProtocolValueError, PublicErrorCode, PublicOperationError

_OLDEST = Timestamp("2026-09-10T00:00:00.000Z")
_OBSERVED = Timestamp("2026-09-10T00:00:05.000Z")
_LATER = Timestamp("2026-09-10T00:00:10.000Z")


def _workspace(store: LocalObservationStore, tmp_path: Path) -> str:
    return store.workspace_commitment(str(tmp_path.resolve()))


def test_capture_backlog_sums_known_routes_and_round_trips(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = _workspace(store, tmp_path)

    store.update_capture_backlog(
        workspace,
        2,
        700,
        _OLDEST,
        _OBSERVED,
        route_id="tsk_route_a",
    )
    store.update_capture_backlog(
        workspace,
        1,
        300,
        _LATER,
        _LATER,
        route_id="tsk_route_b",
    )

    snapshot = store.capture_backlog(workspace)
    assert snapshot["capture_backlog_scope"] == "partial"
    assert snapshot["route_count"] == 2
    assert snapshot["count"] == 3
    assert snapshot["byte_count"] == 1_000
    assert snapshot["oldest_receipt_time"] == _OLDEST.wire
    assert snapshot["observed_at"] == _LATER.wire
    assert store.selection_runtime_status(workspace)["capture_backlog"] == snapshot

    reopened = LocalObservationStore(_state=tmp_path)
    assert reopened.capture_backlog(workspace) == snapshot


def test_unknown_route_keeps_pressure_scope_unknown(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = _workspace(store, tmp_path)

    store.update_capture_backlog(workspace, 1, 4, _OLDEST, _OBSERVED)

    snapshot = store.capture_backlog(workspace)
    assert snapshot["capture_backlog_scope"] == "unknown"
    assert snapshot["count"] == 1
    assert snapshot["byte_count"] == 4


def test_route_cache_saturation_preserves_existing_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(local_mod, "_MAX_CAPTURE_BACKLOG_ROUTES", 1)
    store = LocalObservationStore(_state=tmp_path)
    workspace = _workspace(store, tmp_path)

    store.update_capture_backlog(workspace, 3, 30, _OLDEST, _OBSERVED, route_id="tsk_first")
    store.update_capture_backlog(workspace, 9, 90, _LATER, _LATER, route_id="tsk_second")

    snapshot = store.capture_backlog(workspace)
    assert snapshot["capture_backlog_scope"] == "unknown"
    assert snapshot["route_count"] == 1
    assert snapshot["count"] == 3
    assert snapshot["byte_count"] == 30
    routes = cast(Mapping[str, object], snapshot["routes"])
    assert "tsk_first" in routes
    assert "tsk_second" not in routes


def test_capture_backlog_rejects_invalid_snapshot_values(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = _workspace(store, tmp_path)

    with pytest.raises(ProtocolValueError):
        store.update_capture_backlog(
            workspace,
            -1,
            0,
            None,
            _OBSERVED,
            route_id="tsk_route",
        )
    with pytest.raises(ProtocolValueError):
        store.update_capture_backlog(
            workspace,
            0,
            0,
            None,
            _OBSERVED,
            route_id="unsafe route",
        )


def test_capture_reservation_is_global_across_task_routes_and_releases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(local_mod, "_MAX_CAPTURE_CONTENT_BYTES", 10)
    first = LocalObservationStore(_state=tmp_path)
    second = LocalObservationStore(_state=tmp_path)
    workspace = _workspace(first, tmp_path)
    first_ticket = "sha256:" + "a" * 64
    second_ticket = "sha256:" + "b" * 64

    first.reserve_capture_ticket(workspace, first_ticket, "tsk_first", 7)
    first.confirm_capture_ticket_reservation(workspace, first_ticket, "tsk_first")
    assert second.capture_backlog(workspace)["byte_count"] == 7

    with pytest.raises(PublicOperationError) as exhausted:
        second.reserve_capture_ticket(workspace, second_ticket, "tsk_second", 4)
    assert exhausted.value.code is PublicErrorCode.LIMIT_EXCEEDED

    second.release_capture_ticket_reservation(workspace, first_ticket, "tsk_first")
    second.reserve_capture_ticket(workspace, second_ticket, "tsk_second", 4)
    assert second.capture_backlog(workspace)["byte_count"] == 4


def test_capture_reservation_retry_and_restart_reconcile_are_conservative(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = _workspace(store, tmp_path)
    ticket_id = "sha256:" + "c" * 64

    store.reserve_capture_ticket(workspace, ticket_id, "tsk_recovery", 6)
    # Exact retry is idempotent and does not charge the same ticket twice.
    store.reserve_capture_ticket(workspace, ticket_id, "tsk_recovery", 6)
    with pytest.raises(PublicOperationError) as unknown_update:
        store.reserve_capture_ticket(workspace, ticket_id, "tsk_recovery", 7)
    assert unknown_update.value.code is PublicErrorCode.LIMIT_EXCEEDED
    unknown = store.capture_backlog(workspace)
    assert unknown["capture_backlog_scope"] == "unknown"
    assert unknown["count"] == 1
    assert unknown["byte_count"] == 6

    reopened = LocalObservationStore(_state=tmp_path)
    reopened.reconcile_capture_ticket_reservations(workspace, "tsk_recovery", (ticket_id,))
    reconciled = reopened.capture_backlog(workspace)
    assert reconciled["capture_backlog_scope"] == "partial"
    assert reconciled["reservation_unknown"] is False

    reopened.reconcile_capture_ticket_reservations(workspace, "tsk_recovery", ())
    assert reopened.capture_backlog(workspace)["count"] == 0
