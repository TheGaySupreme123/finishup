"""Deterministic membership and recovery interleavings for hook observation."""

from __future__ import annotations

import asyncio
import io
import json
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Literal, cast

import pytest

from finishup.adapters.integrations.codex_lifecycle import (
    acquire_session_lock,
    acquire_workspace_recovery_lock,
)
from finishup.adapters.integrations.observation_local import (
    LocalObservationStore,
    PendingSessionLifecycle,
)
from finishup.application.observation_drain import ObservationOutboxSweeper
from finishup.cli import observe_hooks as observe_hooks_module
from finishup.cli.observe_hooks import ServiceConnector, handle_observe
from finishup.domain.observation import (
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationIngestResult,
    ObservationSource,
    observation_ingest_result_to_json,
)
from finishup.protocol.models import StartRequest

_START_IDS = {
    "task_id": "tsk_1b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5b",
    "session_id": "ses_1b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5c",
    "writer_id": "wri_1b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5d",
}
_SUCCESSOR_IDS = {
    "task_id": _START_IDS["task_id"],
    "session_id": "ses_2b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5c",
    "writer_id": "wri_2b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5d",
}

_HostCase = tuple[
    ObservationSource,
    Literal["claude", "codex", "cursor"],
    str,
]
_HOST_CASES: tuple[_HostCase, ...] = (
    (ObservationSource.CODEX_HOOK, "codex", "codex"),
    (ObservationSource.CLAUDE_HOOK, "claude", "claude:"),
    (ObservationSource.CURSOR_HOOK, "cursor", "cursor:"),
)


class _RecoveryBarrierClient:
    """Let a recovery attach pause after final local validation and before RPC return."""

    def __init__(self) -> None:
        self.requests: list[StartRequest] = []
        self.rpc_started = threading.Event()
        self.release = threading.Event()
        self._start_count = 0

    async def start(self, request: object, *, deadline_ms: int | None = None) -> object:
        del deadline_ms
        assert isinstance(request, StartRequest)
        self.requests.append(request)
        self._start_count += 1
        assert self._start_count == 1
        assert request.mode == "attach"
        self.rpc_started.set()
        await asyncio.to_thread(self.release.wait, 5)
        return SimpleNamespace(
            ok=True,
            frontier=SimpleNamespace(sequence="4", head_digest="sha256:" + "b" * 64),
            **_SUCCESSOR_IDS,
        )

    async def observation_ingest(self, body: object, *, deadline_ms: int) -> object:
        del body, deadline_ms
        return observation_ingest_result_to_json(
            ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
        )

    async def close(self) -> None:
        return None


class _DuplicateCoordinator:
    """A service-side sweep participant that acknowledges retained envelopes."""

    def __init__(self) -> None:
        self.requests: list[ObservationIngestRequest] = []

    async def ingest_request(self, request: ObservationIngestRequest) -> ObservationIngestResult:
        self.requests.append(request)
        return ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)


def _connector(client: object) -> ServiceConnector:
    async def connect(_kind: object):
        return client

    return cast(ServiceConnector, connect)


def _workspace_and_store(tmp_path: Path) -> tuple[Path, Path, LocalObservationStore, str]:
    state = tmp_path / "state"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(workspace_dir.resolve()))
    store.grant_consent(workspace)
    return state, workspace_dir, store, workspace


def _seed_ended_predecessor(
    store: LocalObservationStore,
    workspace: str,
    predecessor: str,
    *,
    state: Path,
) -> None:
    predecessor_commitment = store.bind_codex_session(workspace, predecessor)
    store.note_session_end(workspace, predecessor_commitment)
    observe_hooks_module.store_mapping(
        observe_hooks_module.mapping_from_start_ids(
            codex_session_id=predecessor,
            finishup_task_id=_START_IDS["task_id"],
            finishup_session_id=_START_IDS["session_id"],
            finishup_writer_id=_START_IDS["writer_id"],
            last_frontier=None,
        ),
        _state=state,
    )


def _payload(session_id: str, event: str, *, tool_name: str = "shell") -> bytes:
    return json.dumps(
        {
            "session_id": session_id,
            "hook_event_name": event,
            "tool_name": tool_name,
            "tool_call_id": f"race-{session_id}",
            "exit_status": 0,
        }
    ).encode()


def _finishup_mutation_tool(source: ObservationSource) -> str:
    if source is ObservationSource.CLAUDE_HOOK:
        return "mcp__plugin_finishup_finishup__publish_work"
    if source is ObservationSource.CURSOR_HOOK:
        return "finishup:publish_work"
    return "mcp__finishup__publish_work"


def _finishup_read_tool(source: ObservationSource) -> str:
    if source is ObservationSource.CLAUDE_HOOK:
        return "mcp__plugin_finishup_finishup__status"
    if source is ObservationSource.CURSOR_HOOK:
        return "finishup:status"
    return "mcp__finishup__status"


def _assert_retained_for_session(
    store: LocalObservationStore,
    workspace: str,
    session_id: str,
    *,
    event_kind: str,
) -> None:
    commitment = store.session_commitment(session_id)
    retained = [
        envelope
        for envelope in store.list_envelopes(workspace)
        if envelope.session_commitment == commitment
    ]
    assert retained
    assert retained[-1].event_kind == event_kind


def _run_service_sweep(store: LocalObservationStore, coordinator: _DuplicateCoordinator) -> None:
    """Run the same bounded service sweeper used by READY maintenance."""

    async def run() -> None:
        sweeper = ObservationOutboxSweeper(store, coordinator)
        try:
            await sweeper.sweep()
        finally:
            sweeper.close()

    asyncio.run(run())


def _pending_intent(
    store: LocalObservationStore,
    workspace: str,
    session_id: str,
    *,
    event_kind: str,
    target_generation: int,
    clear_mapping: bool = False,
) -> PendingSessionLifecycle:
    """Return one exact deferred lifecycle intent from the durable store."""

    intents = store.list_pending_session_lifecycles(workspace, session_id)
    assert intents == (
        PendingSessionLifecycle(
            codex_session_id=session_id,
            session_commitment=store.session_commitment(session_id),
            event_kind=event_kind,
            target_generation=target_generation,
            clear_mapping=clear_mapping,
        ),
    )
    return intents[0]


@pytest.mark.parametrize("event_name", ("SessionStart", "SessionEnd"))
def test_full_deferred_lifecycle_queue_retains_a_session_scoped_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, event_name: str
) -> None:
    state, workspace_dir, store, workspace = _workspace_and_store(tmp_path)
    session_id = "codex-lifecycle-overflow"
    commitment = store.bind_codex_session(workspace, session_id)
    sibling = store.bind_codex_session(workspace, "codex-other-lane")

    def full_queue(*_args: object, **_kwargs: object) -> bool:
        return False

    monkeypatch.setattr(LocalObservationStore, "record_pending_session_lifecycle", full_queue)

    with acquire_session_lock(session_id, _state=state) as owned:
        assert owned
        assert (
            handle_observe(
                event_name=event_name,
                stdin_bytes=_payload(session_id, event_name),
                stdout=io.BytesIO(),
                workspace=str(workspace_dir),
                skip_service=True,
                _state=state,
            )
            == 0
        )
    restored = LocalObservationStore(_state=state)
    assert ObservationGapCode.OUTBOX_OVERFLOW.value in restored.session_gap_codes(
        workspace, commitment
    )
    assert ObservationGapCode.OUTBOX_OVERFLOW.value not in restored.session_gap_codes(
        workspace, sibling
    )
    own_envelopes = [
        item for item in restored.list_envelopes(workspace) if item.session_commitment == commitment
    ]
    assert own_envelopes
    assert ObservationGapCode.OUTBOX_OVERFLOW.value in own_envelopes[-1].gap_codes


@pytest.mark.parametrize(
    ("source", "harness_id", "prefix"),
    _HOST_CASES,
    ids=("codex", "claude", "cursor"),
)
def test_new_session_during_recovery_is_retained_until_membership_can_bind(
    tmp_path: Path,
    source: ObservationSource,
    harness_id: Literal["claude", "codex", "cursor"],
    prefix: str,
) -> None:
    """A raw session arriving after recovery validation stays in its target workspace."""

    state, workspace_dir, store, workspace = _workspace_and_store(tmp_path)
    predecessor = f"{prefix}ended-membership-race"
    successor = f"{prefix}recovery-membership-race"
    raw_session = f"{prefix}raw-membership-race"
    _seed_ended_predecessor(store, workspace, predecessor, state=state)
    client = _RecoveryBarrierClient()
    results: list[int] = []
    errors: list[BaseException] = []

    def run_recovery() -> None:
        try:
            results.append(
                handle_observe(
                    event_name="SessionStart",
                    stdin_bytes=_payload(successor, "SessionStart"),
                    stdout=io.BytesIO(),
                    workspace=str(workspace_dir.resolve()),
                    _state=state,
                    connect=_connector(client),
                    source=source,
                    _output_event_name="sessionStart"
                    if source is ObservationSource.CURSOR_HOOK
                    else None,
                )
            )
        except BaseException as error:  # pragma: no cover - surfaced by the assertion below
            errors.append(error)

    worker = threading.Thread(target=run_recovery)
    worker.start()
    assert client.rpc_started.wait(5), "recovery did not reach the post-validation RPC barrier"

    raw_output = io.BytesIO()
    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=_payload(raw_session, "PostToolUse"),
            stdout=raw_output,
            workspace=str(workspace_dir.resolve()),
            _state=state,
            skip_service=True,
            source=source,
            _output_event_name="afterMCPExecution"
            if source is ObservationSource.CURSOR_HOOK
            else None,
        )
        == 0
    )

    during = LocalObservationStore(_state=state)
    _assert_retained_for_session(during, workspace, raw_session, event_kind="PostToolUse")
    assert raw_session not in during.codex_sessions_for_workspace(workspace)

    client.release.set()
    worker.join(5)
    assert not worker.is_alive(), "recovery did not leave the RPC barrier"
    assert errors == []
    assert results == [0]

    after = LocalObservationStore(_state=state)
    assert successor in after.codex_sessions_for_workspace(workspace)
    # Recovery's own hook may already drain this row; if it returned before a
    # drain slot, the READY sweeper is the durable no-follow-up recovery path.
    coordinator = _DuplicateCoordinator()
    _run_service_sweep(after, coordinator)
    converged = LocalObservationStore(_state=state)
    assert raw_session in converged.codex_sessions_for_workspace(workspace)
    assert converged.list_pending_outbox_rows(workspace) == ()
    _assert_retained_for_session(converged, workspace, raw_session, event_kind="PostToolUse")
    successor_mapping = observe_hooks_module.load_mapping(successor, _state=state)
    assert successor_mapping is not None
    assert successor_mapping.finishup_session_id == _SUCCESSOR_IDS["session_id"]


@pytest.mark.parametrize(
    ("source", "harness_id", "prefix"),
    _HOST_CASES,
    ids=("codex", "claude", "cursor"),
)
def test_session_lock_owned_still_requires_workspace_reservation(
    tmp_path: Path,
    source: ObservationSource,
    harness_id: Literal["claude", "codex", "cursor"],
    prefix: str,
) -> None:
    """The clear-route session lock does not authorize a membership mutation by itself."""

    del harness_id
    state, workspace_dir, store, workspace = _workspace_and_store(tmp_path)
    session_id = f"{prefix}session-lock-owned-race"
    assert store.codex_sessions_for_workspace(workspace) == ()
    with acquire_workspace_recovery_lock(workspace, _state=state) as workspace_owned:
        assert workspace_owned
        with acquire_session_lock(session_id, _state=state) as session_owned:
            assert session_owned
            assert (
                handle_observe(
                    event_name="SessionStart",
                    stdin_bytes=json.dumps(
                        {
                            **json.loads(
                                _payload(
                                    session_id,
                                    "SessionStart",
                                    tool_name=_finishup_read_tool(source),
                                )
                            ),
                            "source": "clear",
                        }
                    ).encode(),
                    stdout=io.BytesIO(),
                    workspace=str(workspace_dir.resolve()),
                    _state=state,
                    skip_service=True,
                    source=source,
                    _output_event_name="sessionStart"
                    if source is ObservationSource.CURSOR_HOOK
                    else None,
                    _session_lock_owned=True,
                )
                == 0
            )
            _pending_intent(
                store,
                workspace,
                session_id,
                event_kind="SessionStart",
                target_generation=1,
                clear_mapping=True,
            )

    after = LocalObservationStore(_state=state)
    assert session_id not in after.codex_sessions_for_workspace(workspace)
    _assert_retained_for_session(after, workspace, session_id, event_kind="SessionStart")
    assert len(after.list_pending_outbox_rows(workspace)) == 1
    assert workspace in after.pending_workspaces()
    coordinator = _DuplicateCoordinator()
    _run_service_sweep(after, coordinator)
    converged = LocalObservationStore(_state=state)
    assert session_id in converged.codex_sessions_for_workspace(workspace)
    assert converged.list_pending_session_lifecycles(workspace) == ()
    assert converged.list_pending_outbox_rows(workspace) == ()
    assert workspace not in converged.pending_workspaces()
    assert len(coordinator.requests) == 1
    generation = converged.current_session_generation(
        workspace, converged.session_commitment(session_id)
    )
    _run_service_sweep(converged, coordinator)
    repeated = LocalObservationStore(_state=state)
    assert (
        repeated.current_session_generation(workspace, repeated.session_commitment(session_id))
        == generation
    )
    assert len(coordinator.requests) == 1


@pytest.mark.parametrize(
    ("source", "harness_id", "prefix"),
    _HOST_CASES,
    ids=("codex", "claude", "cursor"),
)
def test_busy_membership_keeps_event_in_explicit_workspace_with_two_active_workspaces(
    tmp_path: Path,
    source: ObservationSource,
    harness_id: Literal["claude", "codex", "cursor"],
    prefix: str,
) -> None:
    """A contended workspace reservation cannot route a raw event to its sibling workspace."""

    del harness_id
    state, workspace_dir, store, workspace = _workspace_and_store(tmp_path)
    sibling_dir = tmp_path / "sibling-workspace"
    sibling_dir.mkdir()
    sibling = store.workspace_commitment(str(sibling_dir.resolve()))
    store.grant_consent(sibling)
    session_id = f"{prefix}two-workspace-race"

    with acquire_workspace_recovery_lock(workspace, _state=state) as workspace_owned:
        assert workspace_owned
        with acquire_session_lock(session_id, _state=state) as session_owned:
            assert session_owned
            assert (
                handle_observe(
                    event_name="PostToolUse",
                    stdin_bytes=_payload(session_id, "PostToolUse"),
                    stdout=io.BytesIO(),
                    workspace=str(workspace_dir.resolve()),
                    _state=state,
                    skip_service=True,
                    source=source,
                    _output_event_name="afterMCPExecution"
                    if source is ObservationSource.CURSOR_HOOK
                    else None,
                )
                == 0
            )

    after = LocalObservationStore(_state=state)
    _assert_retained_for_session(after, workspace, session_id, event_kind="PostToolUse")
    assert after.list_envelopes(sibling) == ()
    assert session_id not in after.codex_sessions_for_workspace(workspace)
    assert session_id not in after.codex_sessions_for_workspace(sibling)


@pytest.mark.parametrize(
    ("source", "harness_id", "prefix"),
    _HOST_CASES,
    ids=("codex", "claude", "cursor"),
)
def test_busy_session_start_is_retained_and_explains_unmapped_membership(
    tmp_path: Path,
    source: ObservationSource,
    harness_id: Literal["claude", "codex", "cursor"],
    prefix: str,
) -> None:
    """A busy SessionStart keeps its envelope and emits the local-only diagnosis."""

    del harness_id
    state, workspace_dir, store, workspace = _workspace_and_store(tmp_path)
    session_id = f"{prefix}session-start-race"
    output = io.BytesIO()
    assert store.codex_sessions_for_workspace(workspace) == ()

    with acquire_workspace_recovery_lock(workspace, _state=state) as workspace_owned:
        assert workspace_owned
        assert (
            handle_observe(
                event_name="SessionStart",
                stdin_bytes=_payload(session_id, "SessionStart"),
                stdout=output,
                workspace=str(workspace_dir.resolve()),
                _state=state,
                skip_service=True,
                source=source,
                _output_event_name="sessionStart"
                if source is ObservationSource.CURSOR_HOOK
                else None,
            )
            == 0
        )
        _pending_intent(
            store,
            workspace,
            session_id,
            event_kind="SessionStart",
            target_generation=1,
        )

    after = LocalObservationStore(_state=state)
    assert session_id not in after.codex_sessions_for_workspace(workspace)
    _assert_retained_for_session(after, workspace, session_id, event_kind="SessionStart")
    rendered = json.loads(output.getvalue())
    assert "no ledger task is mapped yet" in json.dumps(rendered)


@pytest.mark.parametrize(
    ("source", "harness_id", "prefix"),
    _HOST_CASES,
    ids=("codex", "claude", "cursor"),
)
def test_session_start_reconciles_deferred_membership_and_drains_without_followup_hook(
    tmp_path: Path,
    source: ObservationSource,
    harness_id: Literal["claude", "codex", "cursor"],
    prefix: str,
) -> None:
    """A retained SessionStart is repaired by the READY sweep after contention clears."""

    del harness_id
    state, workspace_dir, store, workspace = _workspace_and_store(tmp_path)
    session_id = f"{prefix}session-start-reconcile-race"
    held = threading.Event()
    release = threading.Event()
    holder_errors: list[BaseException] = []

    def hold_workspace_reservation() -> None:
        try:
            with acquire_workspace_recovery_lock(workspace, _state=state) as owned:
                assert owned
                held.set()
                assert release.wait(5)
        except BaseException as error:  # pragma: no cover - surfaced by the assertion below
            holder_errors.append(error)

    holder = threading.Thread(target=hold_workspace_reservation)
    holder.start()
    assert held.wait(5)

    # A deliverable structural event arrives while the membership reservation is busy.
    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=_payload(
                session_id,
                "PostToolUse",
                tool_name=_finishup_mutation_tool(source),
            ),
            stdout=io.BytesIO(),
            workspace=str(workspace_dir.resolve()),
            _state=state,
            skip_service=True,
            source=source,
            _output_event_name="afterMCPExecution"
            if source is ObservationSource.CURSOR_HOOK
            else None,
        )
        == 0
    )
    assert len(store.list_pending_outbox_rows(workspace)) == 1

    # SessionStart itself is retained as a durable outbox row. No second host
    # event is needed to trigger its membership repair.
    assert (
        handle_observe(
            event_name="SessionStart",
            stdin_bytes=_payload(session_id, "SessionStart"),
            stdout=io.BytesIO(),
            workspace=str(workspace_dir.resolve()),
            _state=state,
            skip_service=True,
            source=source,
            _output_event_name="sessionStart" if source is ObservationSource.CURSOR_HOOK else None,
        )
        == 0
    )
    during = LocalObservationStore(_state=state)
    assert session_id not in during.codex_sessions_for_workspace(workspace)
    assert len(during.list_pending_outbox_rows(workspace)) == 2
    _pending_intent(
        during,
        workspace,
        session_id,
        event_kind="SessionStart",
        target_generation=1,
    )
    assert workspace in during.pending_workspaces()

    release.set()
    holder.join(5)
    assert not holder.is_alive(), "reservation holder did not release"
    assert holder_errors == []

    coordinator = _DuplicateCoordinator()
    _run_service_sweep(store, coordinator)
    after = LocalObservationStore(_state=state)
    assert session_id in after.codex_sessions_for_workspace(workspace)
    assert after.list_pending_outbox_rows(workspace) == ()
    assert after.list_pending_session_lifecycles(workspace) == ()
    assert workspace not in after.pending_workspaces()
    assert len(coordinator.requests) == 2
    _assert_retained_for_session(after, workspace, session_id, event_kind="SessionStart")
    generation = after.current_session_generation(workspace, after.session_commitment(session_id))
    _run_service_sweep(after, coordinator)
    repeated = LocalObservationStore(_state=state)
    assert (
        repeated.current_session_generation(workspace, repeated.session_commitment(session_id))
        == generation
    )
    assert len(coordinator.requests) == 2


@pytest.mark.parametrize(
    ("source", "harness_id", "prefix"),
    _HOST_CASES,
    ids=("codex", "claude", "cursor"),
)
def test_busy_resume_clears_ended_lifecycle_without_followup_hook(
    tmp_path: Path,
    source: ObservationSource,
    harness_id: Literal["claude", "codex", "cursor"],
    prefix: str,
) -> None:
    """A deferred resume must clear the prior ended fence before the host disappears."""

    del harness_id
    state, workspace_dir, store, workspace = _workspace_and_store(tmp_path)
    session_id = f"{prefix}resume-ended-race"
    session_commitment = store.bind_codex_session(workspace, session_id)
    assert store.begin_session_generation(workspace, session_commitment) == 1
    store.note_session_end(workspace, session_commitment)
    assert store.codex_session_ended(workspace, session_id)

    with acquire_workspace_recovery_lock(workspace, _state=state) as workspace_owned:
        assert workspace_owned
        assert (
            handle_observe(
                event_name="SessionStart",
                stdin_bytes=json.dumps(
                    {
                        **json.loads(_payload(session_id, "SessionStart")),
                        "source": "resume",
                    }
                ).encode(),
                stdout=io.BytesIO(),
                workspace=str(workspace_dir.resolve()),
                _state=state,
                skip_service=True,
                source=source,
                _output_event_name="sessionStart"
                if source is ObservationSource.CURSOR_HOOK
                else None,
            )
            == 0
        )
        during = LocalObservationStore(_state=state)
        assert during.codex_session_ended(workspace, session_id)
        assert len(during.list_pending_outbox_rows(workspace)) == 1
        _pending_intent(
            during,
            workspace,
            session_id,
            event_kind="SessionStart",
            target_generation=2,
        )

    coordinator = _DuplicateCoordinator()
    _run_service_sweep(store, coordinator)
    after = LocalObservationStore(_state=state)
    _assert_retained_for_session(after, workspace, session_id, event_kind="SessionStart")
    assert not after.codex_session_ended(workspace, session_id)
    assert after.list_pending_outbox_rows(workspace) == ()
    assert after.list_pending_session_lifecycles(workspace) == ()
    assert len(coordinator.requests) == 1
    generation = after.current_session_generation(workspace, session_commitment)
    _run_service_sweep(after, coordinator)
    repeated = LocalObservationStore(_state=state)
    assert repeated.current_session_generation(workspace, session_commitment) == generation
    assert len(coordinator.requests) == 1


@pytest.mark.parametrize(
    ("source", "harness_id", "prefix"),
    _HOST_CASES,
    ids=("codex", "claude", "cursor"),
)
def test_legacy_ended_resume_uses_implicit_generation_without_followup_hook(
    tmp_path: Path,
    source: ObservationSource,
    harness_id: Literal["claude", "codex", "cursor"],
    prefix: str,
) -> None:
    """A pre-counter ended session resumes at its historical implicit generation one."""

    del harness_id
    state, workspace_dir, store, workspace = _workspace_and_store(tmp_path)
    session_id = f"{prefix}legacy-resume-race"
    session_commitment = store.bind_codex_session(workspace, session_id)
    # Older local state has no persisted session_generations entry.  Its public
    # generation is nevertheless one, and a deferred resume must preserve that
    # value rather than manufacturing generation two.
    store.note_session_end(workspace, session_commitment)
    assert store.current_session_generation(workspace, session_commitment) == 1
    assert store.codex_session_ended(workspace, session_id)

    with acquire_workspace_recovery_lock(workspace, _state=state) as workspace_owned:
        assert workspace_owned
        assert (
            handle_observe(
                event_name="SessionStart",
                stdin_bytes=json.dumps(
                    {
                        **json.loads(_payload(session_id, "SessionStart")),
                        "source": "resume",
                    }
                ).encode(),
                stdout=io.BytesIO(),
                workspace=str(workspace_dir.resolve()),
                _state=state,
                skip_service=True,
                source=source,
                _output_event_name="sessionStart"
                if source is ObservationSource.CURSOR_HOOK
                else None,
            )
            == 0
        )
        during = LocalObservationStore(_state=state)
        assert during.codex_session_ended(workspace, session_id)
        assert len(during.list_pending_outbox_rows(workspace)) == 1
        _pending_intent(
            during,
            workspace,
            session_id,
            event_kind="SessionStart",
            target_generation=1,
        )

    coordinator = _DuplicateCoordinator()
    _run_service_sweep(store, coordinator)
    after = LocalObservationStore(_state=state)
    _assert_retained_for_session(after, workspace, session_id, event_kind="SessionStart")
    assert not after.codex_session_ended(workspace, session_id)
    assert after.current_session_generation(workspace, session_commitment) == 1
    assert after.list_pending_outbox_rows(workspace) == ()
    assert after.list_pending_session_lifecycles(workspace) == ()
    assert len(coordinator.requests) == 1

    _run_service_sweep(after, coordinator)
    repeated = LocalObservationStore(_state=state)
    assert not repeated.codex_session_ended(workspace, session_id)
    assert repeated.current_session_generation(workspace, session_commitment) == 1
    assert len(coordinator.requests) == 1


@pytest.mark.parametrize(
    ("source", "harness_id", "prefix"),
    _HOST_CASES,
    ids=("codex", "claude", "cursor"),
)
def test_busy_session_end_records_lifecycle_without_a_followup_hook(
    tmp_path: Path,
    source: ObservationSource,
    harness_id: Literal["claude", "codex", "cursor"],
    prefix: str,
) -> None:
    """A retained SessionEnd must still close the bound lifecycle after contention clears."""

    del harness_id
    state, workspace_dir, store, workspace = _workspace_and_store(tmp_path)
    session_id = f"{prefix}session-end-race"
    session_commitment = store.bind_codex_session(workspace, session_id)

    with acquire_workspace_recovery_lock(workspace, _state=state) as workspace_owned:
        assert workspace_owned
        assert (
            handle_observe(
                event_name="SessionEnd",
                stdin_bytes=_payload(session_id, "SessionEnd"),
                stdout=io.BytesIO(),
                workspace=str(workspace_dir.resolve()),
                _state=state,
                skip_service=True,
                source=source,
                _output_event_name="sessionEnd"
                if source is ObservationSource.CURSOR_HOOK
                else None,
            )
            == 0
        )
        during = LocalObservationStore(_state=state)
        assert not during.codex_session_ended(workspace, session_id)
        assert len(during.list_pending_outbox_rows(workspace)) == 1
        _pending_intent(
            during,
            workspace,
            session_id,
            event_kind="SessionEnd",
            target_generation=1,
        )

    coordinator = _DuplicateCoordinator()
    _run_service_sweep(store, coordinator)
    after = LocalObservationStore(_state=state)
    _assert_retained_for_session(after, workspace, session_id, event_kind="SessionEnd")
    assert after.codex_session_ended(workspace, session_id)
    assert session_commitment == after.session_commitment(session_id)
    assert after.list_pending_outbox_rows(workspace) == ()
    assert after.list_pending_session_lifecycles(workspace) == ()
    assert len(coordinator.requests) == 1
    generation = after.current_session_generation(workspace, session_commitment)
    _run_service_sweep(after, coordinator)
    repeated = LocalObservationStore(_state=state)
    assert repeated.current_session_generation(workspace, session_commitment) == generation
    assert len(coordinator.requests) == 1


@pytest.mark.parametrize(
    ("source", "harness_id", "prefix"),
    _HOST_CASES,
    ids=("codex", "claude", "cursor"),
)
def test_queued_start_then_end_does_not_resurrect_a_session(
    tmp_path: Path,
    source: ObservationSource,
    harness_id: Literal["claude", "codex", "cursor"],
    prefix: str,
) -> None:
    """A FIFO Start/End pair applies once and leaves the session ended."""

    del harness_id
    state, workspace_dir, store, workspace = _workspace_and_store(tmp_path)
    session_id = f"{prefix}queued-start-end-race"
    held = threading.Event()
    release = threading.Event()
    holder_errors: list[BaseException] = []

    def hold_workspace_reservation() -> None:
        try:
            with acquire_workspace_recovery_lock(workspace, _state=state) as owned:
                assert owned
                held.set()
                assert release.wait(5)
        except BaseException as error:  # pragma: no cover - surfaced by the assertion below
            holder_errors.append(error)

    holder = threading.Thread(target=hold_workspace_reservation)
    holder.start()
    assert held.wait(5)

    for event_name in ("SessionStart", "SessionEnd"):
        assert (
            handle_observe(
                event_name=event_name,
                stdin_bytes=_payload(session_id, event_name),
                stdout=io.BytesIO(),
                workspace=str(workspace_dir.resolve()),
                _state=state,
                skip_service=True,
                source=source,
                _output_event_name={
                    "SessionStart": "sessionStart",
                    "SessionEnd": "sessionEnd",
                }[event_name]
                if source is ObservationSource.CURSOR_HOOK
                else None,
            )
            == 0
        )

    during = LocalObservationStore(_state=state)
    assert session_id not in during.codex_sessions_for_workspace(workspace)
    assert [intent.event_kind for intent in during.list_pending_session_lifecycles(workspace)] == [
        "SessionStart",
        "SessionEnd",
    ]
    assert [
        intent.target_generation for intent in during.list_pending_session_lifecycles(workspace)
    ] == [
        1,
        1,
    ]
    assert len(during.list_pending_outbox_rows(workspace)) == 2
    assert workspace in during.pending_workspaces()

    release.set()
    holder.join(5)
    assert not holder.is_alive(), "reservation holder did not release"
    assert holder_errors == []

    coordinator = _DuplicateCoordinator()
    _run_service_sweep(store, coordinator)
    after = LocalObservationStore(_state=state)
    session_commitment = after.session_commitment(session_id)
    assert session_id in after.codex_sessions_for_workspace(workspace)
    assert after.codex_session_ended(workspace, session_id)
    assert after.current_session_generation(workspace, session_commitment) == 1
    assert after.list_pending_session_lifecycles(workspace) == ()
    assert after.list_pending_outbox_rows(workspace) == ()
    assert workspace not in after.pending_workspaces()
    assert [request.envelope.event_kind for request in coordinator.requests] == [
        "SessionStart",
        "SessionEnd",
    ]

    _run_service_sweep(after, coordinator)
    repeated = LocalObservationStore(_state=state)
    assert repeated.codex_session_ended(workspace, session_id)
    assert repeated.current_session_generation(workspace, session_commitment) == 1
    assert len(coordinator.requests) == 2


def test_stale_deferred_clear_preserves_newer_generation_mapping(tmp_path: Path) -> None:
    state, _directory, store, workspace = _workspace_and_store(tmp_path)
    session_id = "codex-stale-clear"
    _seed_ended_predecessor(store, workspace, session_id, state=state)
    commitment = store.session_commitment(session_id)
    store.begin_session_generation(workspace, commitment)
    store.record_pending_session_lifecycle(
        workspace,
        session_id,
        commitment,
        "SessionStart",
        1,
        clear_mapping=True,
    )
    store.begin_session_generation(workspace, commitment)
    mapping = observe_hooks_module.load_mapping(session_id, _state=state)
    assert mapping is not None
    assert store.reconcile_pending_session_lifecycles(workspace)
    assert observe_hooks_module.load_mapping(session_id, _state=state) == mapping
    assert store.list_pending_session_lifecycles(workspace) == ()
    assert store.current_session_generation(workspace, commitment) == 2
