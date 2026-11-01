"""Outbox delivery lag, enqueue to acceptance, is the exported delivery measure (tb4n5).

The owner kept the 0.2 s hook drain budget and asked for the lag a row actually waits, rather than
a count of hook passes that delivered nothing (``drain_pass_delivered_nothing``), as the measure of
observation delivery. Each outbox row records when it was enqueued; its acknowledgement after the
service accepted it adds one sample.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from pathlib import Path

from finishup.adapters.integrations.observation_local import (
    LocalObservationStore,
    ObservationOutboxRow,
)
from finishup.cli.observe_hooks import map_hook_payload_to_envelope
from finishup.domain.observation import ObservationSource

_START = 1_790_704_600.0


class _Clock:
    def __init__(self) -> None:
        self.now = _START

    def __call__(self) -> float:
        return self.now


def _store(tmp_path: Path) -> tuple[LocalObservationStore, str, _Clock]:
    clock = _Clock()
    store = LocalObservationStore(_state=tmp_path, _wall=clock)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "codex:lag")
    return store, workspace, clock


def _enqueue(store: LocalObservationStore, workspace: str, ordinal: int) -> ObservationOutboxRow:
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "session_id": "codex:lag",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": f"call-lag-{ordinal}",
            "exit_status": 0,
        },
        session_commitment=store.session_commitment("codex:lag"),
        event_ordinal=ordinal,
        key_material=store.key_material(),
        source=ObservationSource.CODEX_HOOK,
    )
    store.enqueue_outbox(workspace, "codex:lag", envelope)
    return store.list_pending_outbox_rows(workspace)[-1]


def test_an_accepted_row_adds_its_enqueue_to_acceptance_lag(tmp_path: Path) -> None:
    store, workspace, clock = _store(tmp_path)
    assert store.delivery_lag(workspace)["count"] == 0

    first = _enqueue(store, workspace, 1)
    assert first.enqueued_at is not None
    clock.now += 1.5
    assert store.acknowledge_outbox_row(workspace, first) is True
    second = _enqueue(store, workspace, 2)
    clock.now += 780  # a row held behind a stuck drain for 13 minutes
    assert store.acknowledge_outbox(workspace, "codex:lag", second.envelope.source_identity)

    lag = store.delivery_lag(workspace)
    assert lag["measured"] == "enqueue_to_accept"
    assert lag["count"] == 2
    assert lag["last_ms"] == 780_000
    assert lag["max_ms"] == 780_000
    assert lag["p50_ms_at_most"] == 2_000
    assert lag["p95_ms_at_most"] == 900_000
    assert lag["since"] == "2026-09-29T17:56:41.500Z"
    # Durable across a restart.
    assert LocalObservationStore(_state=tmp_path).delivery_lag(workspace) == lag


def test_a_retried_row_keeps_its_first_enqueue_and_a_legacy_row_is_not_measured(
    tmp_path: Path,
) -> None:
    store, workspace, clock = _store(tmp_path)
    row = _enqueue(store, workspace, 1)
    clock.now += 4
    retried = store.bump_outbox_row_attempt(workspace, row, reason="service_unavailable")
    assert retried is not None and retried.enqueued_at == row.enqueued_at
    clock.now += 1
    assert store.acknowledge_outbox_row(workspace, retried) is True
    assert store.delivery_lag(workspace)["last_ms"] == 5_000

    legacy = _enqueue(store, workspace, 2)
    state = store._load(workspace)
    assert state.pending_outbox is not None
    state.pending_outbox[-1] = ObservationOutboxRow(legacy.codex_session_id, legacy.envelope)
    store._save(workspace, state)
    (stored,) = store.list_pending_outbox_rows(workspace)
    assert stored.enqueued_at is None
    assert store.acknowledge_outbox_row(workspace, stored) is True
    assert store.delivery_lag(workspace)["count"] == 1
