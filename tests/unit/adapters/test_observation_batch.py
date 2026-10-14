"""Workspace batch savepoints preserve durable state and typed failures."""

from __future__ import annotations

from pathlib import Path

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.domain.observation import ObservationGapCode, ObservationStatusQuery
from finishup.protocol.errors import PublicErrorCode, PublicOperationError


def _store(tmp_path: Path) -> tuple[LocalObservationStore, str]:
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    store = LocalObservationStore(_state=state_root)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    return store, workspace


def test_nested_batch_rolls_back_inner_savepoint_and_preserves_typed_error(
    tmp_path: Path,
) -> None:
    store, workspace = _store(tmp_path)
    outer_gap = ObservationGapCode.SERVICE_UNAVAILABLE.value
    inner_gap = ObservationGapCode.SOURCE_LAG.value
    error = PublicOperationError(
        PublicErrorCode.INVALID_REQUEST,
        "nested operation failed",
        retryable=False,
    )

    with store.batched(workspace):
        store.note_coverage_gap(workspace, outer_gap)
        with pytest.raises(PublicOperationError) as caught:
            with store.batched(workspace):
                store.note_coverage_gap(workspace, inner_gap)
                raise error

        assert caught.value is error
        status = store.status(ObservationStatusQuery(workspace))
        assert outer_gap in status.gaps
        assert inner_gap not in status.gaps

    reopened = LocalObservationStore(_state=tmp_path / "state")
    status = reopened.status(ObservationStatusQuery(workspace))
    assert outer_gap in status.gaps
    assert inner_gap not in status.gaps
