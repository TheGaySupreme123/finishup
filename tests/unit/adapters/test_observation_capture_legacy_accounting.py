"""Legacy capture rows and newly reserved tickets must consume distinct capacity."""

from __future__ import annotations

from pathlib import Path

import pytest

import finishup.adapters.integrations.observation_local as local_mod
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.domain.observation import ObservationCaptureBacklog
from finishup.domain.values import Timestamp
from finishup.protocol.errors import PublicErrorCode, PublicOperationError


@pytest.mark.parametrize("dimension", ["count", "bytes"])
def test_legacy_task_backlog_cannot_hide_a_new_ticket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dimension: str
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    if dimension == "count":
        monkeypatch.setattr(local_mod, "_MAX_CAPTURE_TICKET_RESERVATIONS", 2)
    else:
        monkeypatch.setattr(local_mod, "_MAX_CAPTURE_CONTENT_BYTES", 10)
    store.bootstrap_capture_reservations(
        workspace,
        {"tsk_legacy": ObservationCaptureBacklog(2, 10, Timestamp("2026-09-10T00:00:00.000Z"))},
    )

    # These legacy tickets have no central reservation identities. A distinct
    # new ticket cannot overlap them merely because it belongs to the same task.
    with pytest.raises(PublicOperationError) as exhausted:
        store.reserve_capture_ticket(workspace, "sha256:" + "a" * 64, "tsk_legacy", 1)
    assert exhausted.value.code is PublicErrorCode.LIMIT_EXCEEDED


def test_legacy_ticket_bytes_remain_charged_when_a_known_ticket_grows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    monkeypatch.setattr(local_mod, "_MAX_CAPTURE_CONTENT_BYTES", 10)
    known = "sha256:" + "a" * 64
    legacy = "sha256:" + "b" * 64
    store.reserve_capture_ticket(workspace, known, "tsk_legacy", 7)
    store.confirm_capture_ticket_reservation(workspace, known, "tsk_legacy")
    store.bootstrap_capture_reservations(
        workspace,
        {"tsk_legacy": ObservationCaptureBacklog(2, 10, Timestamp("2026-09-10T00:00:00.000Z"))},
        ticket_ids_by_task={"tsk_legacy": (known, legacy)},
    )

    # Growing the known ticket from seven to ten bytes still leaves three
    # bytes held by the legacy ticket, whose central reservation is absent.
    with pytest.raises(PublicOperationError) as exhausted:
        store.reserve_capture_ticket(workspace, known, "tsk_legacy", 10)
    assert exhausted.value.code is PublicErrorCode.LIMIT_EXCEEDED


def test_ticket_identity_does_not_prove_its_reserved_bytes_are_in_the_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    monkeypatch.setattr(local_mod, "_MAX_CAPTURE_CONTENT_BYTES", 12)
    staging = "sha256:" + "a" * 64
    legacy = "sha256:" + "b" * 64
    store.reserve_capture_ticket(workspace, staging, "tsk_legacy", 10)
    # The staging ticket survived a crash before any of its reserved content
    # was written. The separate legacy ticket owns all ten retained bytes.
    store.bootstrap_capture_reservations(
        workspace,
        {"tsk_legacy": ObservationCaptureBacklog(2, 10, Timestamp("2026-09-10T00:00:00.000Z"))},
        ticket_ids_by_task={"tsk_legacy": (staging, legacy)},
    )

    with pytest.raises(PublicOperationError) as exhausted:
        store.reserve_capture_ticket(workspace, "sha256:" + "c" * 64, "tsk_legacy", 1)
    assert exhausted.value.code is PublicErrorCode.LIMIT_EXCEEDED
