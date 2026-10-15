"""Exact ordering parity with the original outbox lane-selection policy."""

from __future__ import annotations

import random
from collections.abc import Mapping
from typing import cast

import pytest

from finishup.adapters.integrations.observation_local import (
    LocalObservationStore,
    ObservationOutboxRow,
)
from finishup.application.observation_drain import (
    ObservationIngestCoordinator,
    ObservationOutboxSweeper,
)
from finishup.domain.observation import ObservationCursor, ObservationEnvelope, ObservationSource
from finishup.domain.values import JsonObject, Timestamp


def row(session: str, ordinal: int, attempts: int) -> ObservationOutboxRow:
    return ObservationOutboxRow(
        session,
        ObservationEnvelope(
            session_commitment="hmac-sha256:" + "a" * 64,
            event_kind="PostToolUse",
            source_identity=f"hook:{ordinal}",
            source=ObservationSource.CODEX_HOOK,
            cursor=ObservationCursor(
                1, 0, ordinal, "hmac-sha256:" + "b" * 64, "codex-obs-hook/1.0.0"
            ),
            receipt_time=Timestamp("2026-01-01T00:00:00.000Z"),
            structural_payload=JsonObject({"tool_name": "shell"}),
            content_object_refs=(),
            gap_codes=(),
        ),
        attempts=attempts,
    )


class PendingSnapshot:
    def __init__(self, rows: Mapping[str, tuple[ObservationOutboxRow, ...]]) -> None:
        self.rows = rows

    def pending_workspaces(self) -> tuple[str, ...]:
        return tuple(self.rows)

    def list_pending_outbox_rows(self, workspace: str) -> tuple[ObservationOutboxRow, ...]:
        return self.rows[workspace]


def original_selection(
    snapshot: PendingSnapshot, limit: int
) -> tuple[tuple[str, ObservationOutboxRow], ...]:
    """The pre-optimization selection rule, retained as an independent oracle."""
    lanes: dict[tuple[str, str], list[ObservationOutboxRow]] = {}
    for workspace in snapshot.pending_workspaces():
        for item in snapshot.list_pending_outbox_rows(workspace):
            lanes.setdefault((workspace, item.codex_session_id), []).append(item)
    counts = dict.fromkeys(lanes, 0)
    selected: list[tuple[str, ObservationOutboxRow]] = []
    while lanes and len(selected) < limit:
        lane = min(
            lanes,
            key=lambda key: (lanes[key][0].attempts, counts[key], key[0].encode(), key[1].encode()),
        )
        selected.append((lane[0], lanes[lane].pop(0)))
        counts[lane] += 1
        if not lanes[lane]:
            del lanes[lane]
    return tuple(selected)


@pytest.mark.parametrize("seed", range(20))
@pytest.mark.parametrize("limit", [1, 3, 64, 1000])
def test_selection_matches_original_across_fifo_skew_and_ties(seed: int, limit: int) -> None:
    rng = random.Random(seed)
    workspaces = ["z", "a", "é", "אב", "😀", "lifecycle-only"]
    rng.shuffle(workspaces)
    rows: dict[str, tuple[ObservationOutboxRow, ...]] = {}
    for workspace in workspaces:
        pending: list[ObservationOutboxRow] = []
        if workspace != "lifecycle-only":
            for lane in range(rng.randrange(1, 10)):
                session = f"{rng.choice(['a', 'é', 'אב', '😀'])}-{lane}"
                pending.extend(
                    row(session, ordinal, rng.randrange(5))
                    for ordinal in range(1, rng.randrange(2, 15))
                )
        rng.shuffle(pending)
        rows[workspace] = tuple(pending)
    snapshot = PendingSnapshot(rows)
    sweeper = ObservationOutboxSweeper(
        cast(LocalObservationStore, snapshot), cast(ObservationIngestCoordinator, None), limit=limit
    )
    selected, lifecycle = sweeper._fair_pending_rows_and_lifecycle_workspaces()  # pyright: ignore[reportPrivateUsage]
    assert selected == original_selection(snapshot, limit)
    assert lifecycle == tuple(workspaces)
    assert snapshot.rows == rows


def test_empty_pending_snapshot() -> None:
    sweeper = ObservationOutboxSweeper(
        cast(LocalObservationStore, PendingSnapshot({})), cast(ObservationIngestCoordinator, None)
    )
    assert sweeper._fair_pending_rows_and_lifecycle_workspaces() == ((), ())  # pyright: ignore[reportPrivateUsage]
