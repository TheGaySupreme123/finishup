"""A client delivers its own captured observation rows to a server on another machine.

The pass is the service's shared sweeper narrowed to the claimed workspace, with each ingest sent
as ``observation_ingest`` over the client's connection; spooled legacy hook records are replayed
into the outbox first, as the service replays them.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import cast

import pytest

import finishup.cli.observe_hooks as observe_hooks_module
from finishup.adapters.integrations.hook_spool import HookSpool
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.client.observation_outbox import (
    ClientDrainSummary,
    ClientObservationDrain,
    drain_client_observation,
)
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationIngestDisposition,
    ObservationIngestResult,
    ObservationSource,
    observation_ingest_request_from_json,
    observation_ingest_result_to_json,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.ports.control import ControlError, WorkspaceLocator


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _envelope(session: str, identity: str, ordinal: int) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=session,
        event_kind="PostToolUse",
        source_identity=identity,
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(1, 0, ordinal, f"hmac-sha256:{'ab' * 32}", "codex-obs-hook/1.0.0"),
        receipt_time=Timestamp("2026-01-01T00:00:00.000Z"),
        structural_payload=JsonObject(
            {"tool_name": "shell", "tool_call_id": identity, "exit_status": 0}
        ),
        content_object_refs=(),
        gap_codes=(),
    )


def _workspaces(tmp_path: Path) -> tuple[Path, Path, Path]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    claimed = tmp_path / "claimed"
    other = tmp_path / "other"
    claimed.mkdir()
    other.mkdir()
    return state, claimed.resolve(), other.resolve()


def _backlog(store: LocalObservationStore, workspace: Path, *, sessions: int, rows: int) -> str:
    commitment = store.workspace_commitment(os.fspath(workspace))
    store.grant_consent(commitment)
    for lane in range(sessions):
        name = f"{workspace.name}-session-{lane}"
        session = store.bind_codex_session(commitment, name)
        for ordinal in range(1, rows + 1):
            store.enqueue_outbox(
                commitment, name, _envelope(session, f"hook:{name}:{ordinal}", ordinal)
            )
    return commitment


class _Client:
    """Answers ``observation_ingest`` from a script and records each request it was sent."""

    def __init__(self, *, fail_on: int | None = None, failure: str = "service_unavailable") -> None:
        self.requests: list[str] = []
        self._fail_on = fail_on
        self._failure = failure

    async def observation_ingest(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject:
        assert deadline_ms is not None and deadline_ms > 0
        decoded = observation_ingest_request_from_json(request)
        self.requests.append(decoded.envelope.source_identity)
        if self._fail_on is not None and len(self.requests) == self._fail_on:
            raise ControlError(self._failure, retryable=True)
        return observation_ingest_result_to_json(
            ObservationIngestResult(
                ObservationIngestDisposition.ACCEPTED, None, decoded.envelope.cursor
            )
        )


def _pending(store: LocalObservationStore, commitment: str) -> list[tuple[str, int]]:
    return [
        (row.envelope.source_identity, row.attempts)
        for row in store.list_pending_outbox_rows(commitment)
    ]


@pytest.mark.anyio
async def test_only_the_claimed_workspace_is_delivered(tmp_path: Path) -> None:
    state, claimed, other = _workspaces(tmp_path)
    store = LocalObservationStore(_state=state)
    mine = _backlog(store, claimed, sessions=2, rows=2)
    theirs = _backlog(store, other, sessions=1, rows=2)
    client = _Client()

    summary = await drain_client_observation(
        client, WorkspaceLocator(os.fspath(claimed)), state=state
    )

    assert summary.stopped is None and summary.spool_replayed == 0
    assert summary.delivery is not None
    assert (summary.delivery.attempted, summary.delivery.acknowledged) == (4, 4)
    assert sorted(client.requests) == sorted(
        f"hook:claimed-session-{lane}:{ordinal}" for lane in range(2) for ordinal in (1, 2)
    )
    assert _pending(store, mine) == []
    # Another workspace's rows belong to another connection's claim: untouched.
    assert _pending(store, theirs) == [
        ("hook:other-session-0:1", 0),
        ("hook:other-session-0:2", 0),
    ]


@pytest.mark.anyio
async def test_a_control_failure_stops_the_pass_without_charging_later_rows(
    tmp_path: Path,
) -> None:
    state, claimed, _other = _workspaces(tmp_path)
    store = LocalObservationStore(_state=state)
    mine = _backlog(store, claimed, sessions=3, rows=1)
    client = _Client(fail_on=1)
    drain = ClientObservationDrain(WorkspaceLocator(os.fspath(claimed)), state=state)
    try:
        stopped = await drain.drain(client)
        assert stopped == ClientDrainSummary(0, None, "service_unavailable")
        assert len(client.requests) == 1
        attempts = dict(_pending(store, mine))
        assert attempts[client.requests[0]] == 1  # the failed row was charged, as the CLI does
        assert sorted(attempts.values()) == [0, 0, 1]  # nothing else was

        # The next pass over a working connection delivers everything still pending.
        healthy = _Client()
        summary = await drain.drain(healthy)
        assert summary.stopped is None and summary.delivery is not None
        assert summary.delivery.acknowledged == 3
        assert _pending(store, mine) == []
    finally:
        drain.close()


@pytest.mark.anyio
async def test_a_failure_on_the_last_attempt_keeps_its_summary(tmp_path: Path) -> None:
    state, claimed, _other = _workspaces(tmp_path)
    store = LocalObservationStore(_state=state)
    _backlog(store, claimed, sessions=1, rows=1)
    summary = await drain_client_observation(
        _Client(fail_on=1, failure="vault_locked"),
        WorkspaceLocator(os.fspath(claimed)),
        state=state,
    )
    assert summary.stopped == "vault_locked"
    assert summary.delivery is not None
    assert (summary.delivery.attempted, summary.delivery.retry_pending) == (1, 1)


@pytest.mark.anyio
async def test_nothing_captured_means_nothing_to_send(tmp_path: Path) -> None:
    state, claimed, _other = _workspaces(tmp_path)
    client = _Client()
    summary = await drain_client_observation(
        client, WorkspaceLocator(os.fspath(claimed)), state=state
    )
    assert summary.delivery is not None and summary.delivery.attempted == 0
    assert client.requests == []
    assert not (state / "observation" / "key-material.bin").exists()


@pytest.mark.anyio
async def test_spooled_records_of_the_claimed_workspace_are_replayed_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, claimed, other = _workspaces(tmp_path)
    store = LocalObservationStore(_state=state)
    mine = store.workspace_commitment(os.fspath(claimed))
    theirs = store.workspace_commitment(os.fspath(other))
    spool = HookSpool(_state=state)
    for index in range(3):
        assert spool.append(
            workspace=os.fspath(claimed),
            event_name="PostToolUse",
            payload={"session_id": f"codex-{index}"},
        )
    assert spool.append(
        workspace=os.fspath(other), event_name="PostToolUse", payload={"session_id": "codex-x"}
    )
    replayed: list[tuple[str | None, str | None, bool]] = []

    def handle_observe(**kwargs: object) -> int:
        replayed.append(
            (
                cast(str, kwargs["event_name"]),
                cast(str, kwargs["_workspace_commitment"]),
                kwargs["skip_service"] is True,
            )
        )
        return 0

    monkeypatch.setattr(observe_hooks_module, "handle_observe", handle_observe)
    drain = ClientObservationDrain(
        WorkspaceLocator(os.fspath(claimed)), state=state, spool_batch_limit=2
    )
    try:
        first = await drain.drain(_Client())
        second = await drain.drain(_Client())
        third = await drain.drain(_Client())
    finally:
        drain.close()
    assert (first.spool_replayed, second.spool_replayed, third.spool_replayed) == (2, 1, 0)
    assert replayed == [("PostToolUse", mine, True)] * 3
    assert spool.has_pending(theirs)


@pytest.mark.anyio
async def test_a_failing_spool_replay_does_not_stop_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, claimed, _other = _workspaces(tmp_path)
    store = LocalObservationStore(_state=state)
    mine = _backlog(store, claimed, sessions=1, rows=1)
    assert HookSpool(_state=state).append(
        workspace=os.fspath(claimed), event_name="PostToolUse", payload={"session_id": "codex-1"}
    )

    def broken(**_kwargs: object) -> int:
        raise OSError("disk detail that must not travel")

    monkeypatch.setattr(observe_hooks_module, "handle_observe", broken)
    summary = await drain_client_observation(
        _Client(), WorkspaceLocator(os.fspath(claimed)), state=state
    )
    assert summary.spool_replayed == 0
    assert summary.delivery is not None and summary.delivery.acknowledged == 1
    assert _pending(store, mine) == []
    # The batch stays in the spool for a later pass.
    assert HookSpool(_state=state).has_pending(mine)


def test_drain_settings_are_validated(tmp_path: Path) -> None:
    locator = WorkspaceLocator(os.fspath(tmp_path))
    with pytest.raises(TypeError, match="workspace_locator_invalid"):
        ClientObservationDrain(os.fspath(tmp_path))  # pyright: ignore[reportArgumentType]
    with pytest.raises(ValueError, match="observation_sweep_budget_invalid"):
        ClientObservationDrain(locator, budget_seconds=0.0)
    with pytest.raises(ValueError, match="observation_ingest_deadline_invalid"):
        ClientObservationDrain(locator, ingest_deadline_ms=0)
    with pytest.raises(ValueError, match="hook_spool_claim_limit_invalid"):
        ClientObservationDrain(locator, spool_batch_limit=0)
