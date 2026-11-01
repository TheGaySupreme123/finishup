"""tb4n1 B4/C6: content staging under a contended lease, and the drain finished at Stop.

In tb4n1 (Codex, 72 FinishUP attempts) `drain_budget_exhausted` fired on 10,835 of 11,556 hooks,
`content_capture_unavailable` reached 72/72 attempts, and 39/40 closure-gate texts said
"observations were still draining", so the planned-verification gate tokens never fired.
"""

from __future__ import annotations

import io
import json
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from finishup.adapters.integrations.codex_lifecycle import mapping_from_start_ids, store_mapping
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli import observe_hooks as observe_hooks_module
from finishup.cli.observe_hooks import map_hook_payload_to_envelope
from finishup.domain.observation import (
    OBSERVATION_CONTENT_CAPTURE_PENDING_REASON,
    ObservationContentChunk,
    ObservationContentKind,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestResult,
    ObservationSource,
    ObservationStatusQuery,
    observation_ingest_result_to_json,
)
from finishup.kernel.task_facts import PLANNED_VERIFICATION_NOT_OBSERVED_GAP
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.ids import IdKind, new_id

_DIGEST = "sha256:" + "e" * 64


def _envelope(store: LocalObservationStore, session: str, ordinal: int, source: ObservationSource):
    return map_hook_payload_to_envelope(
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
        source=source,
    )


def _diagnostic_reasons(state: Path) -> list[str]:
    path = state / "observation" / "hook-diagnostics.jsonl"
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text().splitlines() if line]
    return [str(row.get("reason")) for row in rows]


# --- content staged while another owner holds the drain lease ---------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("staged_reason", [OBSERVATION_CONTENT_CAPTURE_PENDING_REASON, None])
async def test_contended_lease_still_stages_transient_content(
    tmp_path: Path, staged_reason: str | None
) -> None:
    """Codex runs hooks concurrently; losing the lease no longer loses this hook's bytes."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = "codex:contended"
    store.bind_codex_session(workspace, session)
    current = _envelope(store, session, 1, ObservationSource.CODEX_HOOK)
    store.enqueue_outbox(workspace, session, current)
    chunk = ObservationContentChunk(
        content_kind=ObservationContentKind.TOOL_OUTPUT,
        correlation_identity=f"{current.source_identity}:tool-output",
        source_commitment=current.cursor.last_source_commitment,
        media_type="text/plain",
        part_index=0,
        part_count=1,
        content=b"command output that has no durable outbox carrier",
    )
    calls: list[Mapping[str, object]] = []

    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int) -> object:
            del deadline_ms
            calls.append(cast(Mapping[str, object], body))
            if staged_reason is None:
                return observation_ingest_result_to_json(
                    ObservationIngestResult(
                        ObservationIngestDisposition.REJECTED,
                        ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                        None,
                    )
                )
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.REJECTED, staged_reason, None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object) -> Client:
        return Client()

    with store.drain_lease(workspace) as held:
        assert held, "the test plays the concurrent owner"
        owned = await observe_hooks_module._drain_outbox(  # pyright: ignore[reportPrivateUsage]
            store,
            workspace_commitment=workspace,
            codex_session_id=session,
            content_by_source_identity={current.source_identity: (chunk,)},
            content_capture_profile=None,
            connect=connect,  # type: ignore[arg-type]
            monotonic=lambda: 0.0,
            _state=tmp_path,
        )
    assert owned is False
    assert len(calls) == 1
    assert calls[0].get("capture_only") is True
    assert calls[0].get("content_chunks")
    # The structural row stays for the lease owner or the sweeper; the cursor never moved.
    assert len(store.list_pending_outbox_rows(workspace)) == 1
    gaps = store.status(ObservationStatusQuery(workspace)).gaps
    if staged_reason is None:
        assert ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value in gaps
    else:
        assert ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value not in gaps


# --- the drain finished at Stop, per host ------------------------------------------------------


class _Host:
    def __init__(self, name: str) -> None:
        self.name = name

    def key(self, session: str) -> str:
        return session if self.name == "codex" else f"{self.name}:{session}"

    def source(self) -> ObservationSource:
        return {
            "codex": ObservationSource.CODEX_HOOK,
            "claude": ObservationSource.CLAUDE_HOOK,
            "cursor": ObservationSource.CURSOR_HOOK,
        }[self.name]

    def handler(self) -> Any:
        return {
            "codex": observe_hooks_module.handle_observe,
            "claude": observe_hooks_module.handle_claude_observe,
            "cursor": observe_hooks_module.handle_cursor_observe,
        }[self.name]

    def event(self) -> str:
        return "stop" if self.name == "cursor" else "Stop"

    def body(self, session: str) -> dict[str, JsonValue]:
        if self.name == "cursor":
            return {
                "conversation_id": session,
                "cursor_version": "3.17.8",
                "status": "completed",
                "loop_count": 0,
            }
        return {"session_id": session, "stop_hook_active": False}

    def gate_text(self, output: Mapping[str, Any]) -> str:
        if self.name == "codex":
            return cast(str, output.get("reason", ""))
        if self.name == "claude":
            return cast(
                str,
                cast(Mapping[str, Any], output.get("hookSpecificOutput", {})).get(
                    "additionalContext", ""
                ),
            )
        return cast(str, output.get("followup_message", ""))


@pytest.fixture(params=["codex", "claude", "cursor"])
def host(request: pytest.FixtureRequest) -> _Host:
    return _Host(cast(str, request.param))


def _run_stop(
    tmp_path: Path,
    host: _Host,
    *,
    backlog: int,
    foreign_backlog: int = 0,
    refuse_own: bool = False,
) -> tuple[Mapping[str, Any], LocalObservationStore, str, list[str]]:
    session = "stop-drain"
    host_key = host.key(session)
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=host_key,
            finishup_task_id=new_id(IdKind.TASK),
            finishup_session_id=new_id(IdKind.SESSION),
            finishup_writer_id=new_id(IdKind.WRITER),
            last_frontier="0:genesis",
        ),
        _state=tmp_path,
    )
    store.bind_codex_session(workspace, host_key)
    for ordinal in range(1, backlog + 1):
        store.enqueue_outbox(
            workspace, host_key, _envelope(store, host_key, ordinal, host.source())
        )
    # Another, unmapped host session in the same workspace: its rows can never reach this
    # task's ledger, so they must not hold this task's Stop decision.
    foreign = "foreign-session"
    if foreign_backlog:
        store.bind_codex_session(workspace, foreign)
    for ordinal in range(1, foreign_backlog + 1):
        store.enqueue_outbox(
            workspace, foreign, _envelope(store, foreign, ordinal, ObservationSource.CODEX_HOOK)
        )
    foreign_commitment = store.session_commitment(foreign)
    readiness = SimpleNamespace(
        state="action_required",
        agent_actionable=(PLANNED_VERIFICATION_NOT_OBSERVED_GAP,),
        open_obligation_count="0",
        receipt_blocking_finding_count="0",
    )
    delivered: list[str] = []

    class Client:
        async def status(self, request: object, *, deadline_ms: int | None = None) -> object:
            del request, deadline_ms
            return SimpleNamespace(
                root=SimpleNamespace(
                    head_frontier=SimpleNamespace(sequence="9", head_digest=_DIGEST),
                    closure_readiness=readiness,
                    task_id=new_id(IdKind.TASK),
                )
            )

        async def observation_ingest(self, body: object, *, deadline_ms: int) -> object:
            del deadline_ms
            envelope = cast(Mapping[str, Any], cast(Mapping[str, Any], body)["envelope"])
            own = envelope.get("session_commitment") != foreign_commitment
            if not own or refuse_own:
                return observation_ingest_result_to_json(
                    ObservationIngestResult(
                        ObservationIngestDisposition.REJECTED,
                        ObservationGapCode.MAPPING_MISSING.value
                        if not own
                        else ObservationGapCode.SERVICE_UNAVAILABLE.value,
                        None,
                    )
                )
            delivered.append(cast(str, envelope.get("source_identity")))
            return observation_ingest_result_to_json(
                ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object) -> Client:
        return Client()

    stdout = io.BytesIO()
    code = host.handler()(
        event_name=host.event(),
        stdin_bytes=canonical_encode({"hook_event_name": host.event(), **host.body(session)}),
        stdout=stdout,
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,
    )
    assert code == 0
    output = cast(Mapping[str, Any], json.loads(stdout.getvalue().decode() or "{}"))
    return output, store, workspace, delivered


def test_stop_drains_the_task_backlog_so_the_gate_uses_observed_facts(
    tmp_path: Path, host: _Host
) -> None:
    """A backlog larger than any ordinary hook slice is delivered inside the Stop window."""

    output, store, workspace, delivered = _run_stop(tmp_path, host, backlog=20, foreign_backlog=3)
    assert len(delivered) >= 20
    own_left = [
        row
        for row in store.list_pending_outbox_rows(workspace)
        if row.codex_session_id == host.key("stop-drain")
    ]
    assert own_left == []
    reasons = _diagnostic_reasons(tmp_path)
    assert "stop_drain_complete" in reasons
    assert "closure_gate_continued" in reasons
    text = host.gate_text(output)
    assert "planned verification" in text
    assert "still draining" not in text


def test_stop_with_a_blocked_backlog_is_bounded_and_says_so(tmp_path: Path, host: _Host) -> None:
    """A retryable refusal ends the Stop drain at once; the gate stays honest about pending rows."""

    output, store, workspace, delivered = _run_stop(tmp_path, host, backlog=3, refuse_own=True)
    assert delivered == []
    assert store.pending_outbox_count(workspace) >= 1
    reasons = _diagnostic_reasons(tmp_path)
    assert "stop_drain_incomplete" in reasons
    text = host.gate_text(output)
    assert "planned verification" not in text


def test_stop_does_not_wait_out_its_window_behind_a_stalled_lease_holder(
    tmp_path: Path, host: _Host
) -> None:
    """Another owner holds the drain lease and moves nothing: Stop gives up after a short stall.

    The gate still decides (with observed-run facts withheld, since rows remain pending) instead
    of the Stop pass spending its whole window polling.
    """

    import threading
    import time

    holder = LocalObservationStore(_state=tmp_path)
    workspace = holder.workspace_commitment(str(tmp_path.resolve()))
    holder.grant_consent(workspace)
    ready = threading.Event()
    release = threading.Event()

    def hold() -> None:
        with holder.drain_lease(workspace) as owned:
            assert owned
            ready.set()
            release.wait(30)

    thread = threading.Thread(target=hold)
    thread.start()
    assert ready.wait(5)
    started = time.monotonic()
    try:
        output, _store, _workspace, delivered = _run_stop(tmp_path, host, backlog=5)
    finally:
        release.set()
        thread.join(5)
    elapsed = time.monotonic() - started
    assert delivered == []
    reasons = _diagnostic_reasons(tmp_path)
    assert "stop_drain_incomplete" in reasons
    assert "closure_gate_budget_exhausted" not in reasons
    # The only remaining item is observation-dependent, so with rows still pending the gate
    # decides "not required" rather than claiming the verification was never run.
    assert "closure_gate_not_required" in reasons
    assert "planned verification" not in host.gate_text(output)
    # Bounded by the stall allowance, not the ~4 s Stop drain deadline.
    assert elapsed < 3.0, elapsed


@pytest.mark.anyio
async def test_stop_keeps_waiting_while_a_slow_owner_moves_other_rows_first(
    tmp_path: Path,
) -> None:
    """Review of #994: progress is any outbox movement, not only this task's count dropping."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    ours = "ours"
    session_id = new_id(IdKind.SESSION)
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=ours,
            finishup_task_id=new_id(IdKind.TASK),
            finishup_session_id=session_id,
            finishup_writer_id=new_id(IdKind.WRITER),
            last_frontier="0:genesis",
        ),
        _state=tmp_path,
    )
    store.bind_codex_session(workspace, ours)
    store.bind_codex_session(workspace, "other")
    for ordinal in range(1, 4):
        store.enqueue_outbox(
            workspace, "other", _envelope(store, "other", ordinal, ObservationSource.CODEX_HOOK)
        )
    store.enqueue_outbox(workspace, ours, _envelope(store, ours, 1, ObservationSource.CODEX_HOOK))

    clock = {"now": 0.0}
    calls = 0

    async def owner_moves_one_row(*_args: object, **_kwargs: object) -> bool:
        # Another owner holds the lease and acknowledges one row (oldest first) every 0.9 s.
        nonlocal calls
        calls += 1
        clock["now"] += 0.9
        (head, *_rest) = store.list_pending_outbox_rows(workspace)
        store.acknowledge_outbox_row(workspace, head)
        return False

    original = observe_hooks_module._drain_outbox  # pyright: ignore[reportPrivateUsage]
    observe_hooks_module._drain_outbox = owner_moves_one_row  # type: ignore[assignment]
    try:
        left = await observe_hooks_module._finish_stop_drain(  # pyright: ignore[reportPrivateUsage]
            store,
            workspace_commitment=workspace,
            codex_session_id=ours,
            finishup_session_id=session_id,
            connect=None,
            _state=tmp_path,
            deadline=10.0,
            monotonic=lambda: clock["now"],
            session_lock_owned=False,
        )
    finally:
        observe_hooks_module._drain_outbox = original  # type: ignore[assignment]
    assert left == 0
    assert calls == 4
