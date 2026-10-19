"""Shared real-coordinator replay harness for Codex hook and rollout sessions (#917, #1019, #1027).

A consented Codex workspace, its rollout file, and one task ledger behind the real
``ObservationCoordinator``. Hook payloads go through ``observe_hooks.handle_observe``, rollout
lines through the session-stream reader those hooks trigger, and every outbox row through the real
sweeper and coordinator. Extracted from ``test_codex_code_mode_replay`` so the compaction
conformance tests and the real-run replay script drive the same path.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import io
import json
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, cast

import apsw
import pytest

from builders.ledger_adapters import FixedClock, FixedIds, MemoryObjects, ownership_fence
from finishup.adapters.integrations.codex_lifecycle import LifecycleMapping
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.adapters.memory.importer import MemoryImportState
from finishup.adapters.memory.ledger import MemoryLedgerAdapter, MemoryLedgerState
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.observation import SqliteObservationStore
from finishup.application.observation_coordinator import ObservationCoordinator
from finishup.application.observation_drain import ObservationOutboxSweeper
from finishup.cli import observe_hooks
from finishup.domain.events import AcceptedEvent
from finishup.domain.observation import (
    ObservationContentChunk,
    ObservationContentKind,
    ObservationEnvelope,
    ObservationIngestRequest,
    ObservationIngestResult,
    ObservationSource,
)
from finishup.ports.runtime import RuntimeCapability, TaskRuntime
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.ids import PREFIX_BY_KIND, IdKind

HOST = "019f9b27-c1de-7a61-9c5e-5d0b89759417"
WALL_START = 1_790_704_600.0


def rollout_row(wrapper: str, payload: dict[str, Any], timestamp: str) -> dict[str, Any]:
    return {"payload": payload, "timestamp": timestamp, "type": wrapper}


def exec_cell(
    call_id: str, source: str, timestamp: str, *, item_id: str | None = None
) -> dict[str, Any]:
    """The model's code-mode cell as the rollout records it.

    Without ``item_id`` this is the 0.157.1 shape (``call_id`` only). Codex 0.159.3 also names the
    row itself, ``id: ctc_...``, beside the ``call_id`` its output shares (#1038): pass ``item_id``
    for that shape.
    """

    payload: dict[str, Any] = {
        "call_id": call_id,
        "input": source,
        "name": "exec",
        "status": "completed",
        "type": "custom_tool_call",
    }
    if item_id is not None:
        payload["id"] = item_id
    return rollout_row("response_item", payload, timestamp)


def exec_cell_output(
    call_id: str, result: str, timestamp: str, *, item_id: str | None = None
) -> dict[str, Any]:
    """The cell's output row; ``item_id`` adds the 0.159.3 row id (``ctco_...``, #1038)."""

    payload: dict[str, Any] = {
        "call_id": call_id,
        "output": [
            {
                "text": "Script completed\nWall time 25.3 seconds\nOutput:\n",
                "type": "input_text",
            },
            {"text": result, "type": "input_text"},
        ],
        "type": "custom_tool_call_output",
    }
    if item_id is not None:
        payload["id"] = item_id
    return rollout_row("response_item", payload, timestamp)


def mcp_tool_call(
    item_id: str,
    tool: str,
    timestamp: str,
    *,
    server: str | None = "finishup",
    status: str = "completed",
) -> dict[str, Any]:
    """The nested ``McpToolCall`` item Codex 0.159.3 writes for a code-mode MCP call.

    ``server=None`` omits the ``server`` field: the reader then names the item by its tool alone.
    """

    item: dict[str, Any] = {
        "arguments": {},
        "duration": {"nanos": 105_009_526, "secs": 0},
        "id": item_id,
        "readOnlyHint": False,
        "result": {"content": [{"text": "public synthetic", "type": "text"}]},
        "status": status,
        "tool": tool,
        "type": "McpToolCall",
    }
    if server is not None:
        item["server"] = server
    return rollout_row(
        "event_msg",
        {
            "completed_at_ms": 1_790_704_690_742,
            "item": item,
            "started_at_ms": 1_790_704_667_516,
            "thread_id": HOST,
            "turn_id": "turn_1",
            "type": "item_completed",
        },
        timestamp,
    )


def command_execution(item_id: str, command: str, exit_code: int, timestamp: str) -> dict[str, Any]:
    """The nested ``CommandExecution`` item Codex writes for a code-mode shell call."""

    return rollout_row(
        "event_msg",
        {
            "completed_at_ms": 1_790_704_690_742,
            "item": {
                "command": ["/bin/bash", "-lc", command],
                "cwd": "file:///app",
                "duration": {"nanos": 226_084_509, "secs": 23},
                "exit_code": exit_code,
                "id": item_id,
                "parsed_cmd": [{"cmd": command, "type": "unknown"}],
                "source": "unified_exec_startup",
                "status": "failed" if exit_code else "completed",
                "stderr": "",
                "stdout": "public synthetic output",
                "type": "CommandExecution",
            },
            "started_at_ms": 1_790_704_667_516,
            "thread_id": HOST,
            "turn_id": "turn_1",
            "type": "item_completed",
        },
        timestamp,
    )


@dataclass
class Replay:
    """A consented Codex workspace, its rollout, and one task ledger behind a real coordinator."""

    root: Path
    workspace: Path
    rollout: Path
    store: LocalObservationStore
    commitment: str
    session: str
    task_id: str
    mapping: LifecycleMapping
    ledger: MemoryLedgerAdapter
    ids: FixedIds
    objects: MemoryObjects
    task_store: SqliteObservationStore
    wall: list[float] = field(default_factory=lambda: [WALL_START])

    def append(self, *rows: dict[str, Any]) -> None:
        with self.rollout.open("ab") as handle:
            for row in rows:
                handle.write(json.dumps(row, separators=(",", ":"), sort_keys=True).encode())
                handle.write(b"\n")

    def hook(self, event: str, **fields: Any) -> None:
        payload: dict[str, Any] = {
            "cwd": str(self.workspace),
            "hook_event_name": event,
            "model": "gpt-6-sol",
            "permission_mode": "bypassPermissions",
            "session_id": HOST,
            "transcript_path": str(self.rollout),
            **fields,
        }
        assert (
            observe_hooks.handle_observe(
                event_name=event,
                stdin_bytes=canonical_encode(payload),
                stdout=io.BytesIO(),
                workspace=str(self.workspace),
                _state=self.root,
                skip_service=True,
            )
            == 0
        )

    def advance(self, seconds: float) -> None:
        self.wall[0] += seconds

    def rows(self, name: str) -> list[AcceptedEvent]:
        return [
            row
            for row in self.ledger._state.records
            if type(row) is AcceptedEvent and row.schema.name == name
        ]


def make_replay(base: Path, monkeypatch: pytest.MonkeyPatch) -> Replay:
    """Build a consented Codex workspace, rollout and task ledger under the existing ``base``.

    ``base`` must be a real (symlink-free), owner-only directory: the local store refuses
    anything else. The fixture below uses pytest's ``tmp_path``; the real-run replay script
    (tb4n3 N3-7) passes an isolated directory of its own.
    """

    workspace = base / "workspace"
    workspace.mkdir()
    home = base / "codex-home"
    sessions = home / "sessions" / "2026" / "09" / "29"
    sessions.mkdir(parents=True)
    home.chmod(0o700)
    rollout = sessions / f"rollout-2026-09-29T17-54-00-{HOST}.jsonl"
    rollout.write_bytes(b"")
    rollout.chmod(0o600)
    monkeypatch.setenv("CODEX_HOME", str(home))
    root = base / "isolated"
    store = LocalObservationStore(_state=root)
    commitment = store.workspace_commitment(str(workspace.resolve()))
    store.grant_consent(commitment)
    session = store.bind_codex_session(commitment, HOST)
    task_id = PREFIX_BY_KIND[IdKind.TASK] + str(uuid.uuid4())
    mapping = LifecycleMapping(
        mapping_version=1,
        codex_session_id=HOST,
        finishup_task_id=task_id,
        finishup_session_id=PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4()),
        finishup_writer_id=PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4()),
        last_frontier=None,
    )
    ids = FixedIds()
    objects = MemoryObjects(ids)
    ledger = MemoryLedgerAdapter(
        task_id=task_id,
        ownership_fence=ownership_fence(),
        state=MemoryLedgerState(),
        import_state=MemoryImportState(),
        transaction_lock=asyncio.Lock(),
        clock=FixedClock(),
        ids=ids,
        objects=objects,
    )
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": task_id, "owner_generation": "1"})
    cell = Replay(
        root,
        workspace,
        rollout,
        store,
        commitment,
        session,
        task_id,
        mapping,
        ledger,
        ids,
        objects,
        SqliteObservationStore(db),
    )

    # The admission buffer's five-second pending-attempt deadline runs on the
    # store's wall clock; the replay advances it the way the host session did.
    def _replay_wall(_store: LocalObservationStore) -> float:
        return cell.wall[0]

    monkeypatch.setattr(LocalObservationStore, "_wall_now", _replay_wall)
    return cell


@pytest.fixture(name="replay")
def replay_cell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Replay]:
    yield make_replay(tmp_path, monkeypatch)


def build_coordinator(cell: Replay) -> ObservationCoordinator:
    class _RuntimePort:
        async def route(self, command: object) -> TaskRuntime:
            return TaskRuntime(
                cell.task_id,
                cast(str, getattr(command, "session_id")),
                cast(str, getattr(command, "writer_id")),
                frozenset(
                    {
                        RuntimeCapability.STRUCTURAL_READ,
                        RuntimeCapability.PAYLOAD_READ,
                        RuntimeCapability.WRITE,
                    }
                ),
                cell.ledger,
                cell.objects,  # type: ignore[arg-type]
                object(),  # type: ignore[arg-type]
                "0.1.0",
                "0.1.0",
                "0.1",
                "1.0.0",
                ownership_fence(),
                observation=cell.task_store,
            )

        async def release(self, released: object) -> None:
            del released

    class _Coordinator(ObservationCoordinator):
        async def _enqueue_verification(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

        async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

    return _Coordinator(
        runtime=_RuntimePort(),  # type: ignore[arg-type]
        local=cell.store,
        clock=FixedClock(),  # type: ignore[arg-type]
        ids=cell.ids,  # type: ignore[arg-type]
        state_root=cell.root,
        mapping_loader=lambda *_args, **_kwargs: cell.mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )


class Recorder:
    """Deliver every outbox row to the real coordinator and keep what it answered.

    ``capture_hook_output`` models a content-capturing host (ADR-006 native capture): every
    Codex ``PostToolUse`` row is delivered with its tool output as one inline content chunk, so
    its committed role set carries a captured-evidence role that a contentless copy lacks.
    """

    def __init__(
        self, coordinator: ObservationCoordinator, *, capture_hook_output: bool = False
    ) -> None:
        self.coordinator = coordinator
        self.capture_hook_output = capture_hook_output
        self.delivered: list[ObservationEnvelope] = []
        self.answers: list[tuple[str, str, str, str | None]] = []

    @property
    def refused(self) -> list[tuple[str, str, str, str | None]]:
        """Every row the coordinator did not accept or recognize as a duplicate."""

        return [item for item in self.answers if item[2] not in {"accepted", "duplicate"}]

    async def ingest_request(self, request: ObservationIngestRequest) -> ObservationIngestResult:
        envelope = request.envelope
        if (
            self.capture_hook_output
            and envelope.source is ObservationSource.CODEX_HOOK
            and envelope.event_kind == "PostToolUse"
        ):
            request = replace(
                request,
                content_chunks=(
                    ObservationContentChunk(
                        content_kind=ObservationContentKind.TOOL_OUTPUT,
                        correlation_identity=f"{envelope.source_identity}:tool-output",
                        source_commitment=envelope.cursor.last_source_commitment,
                        media_type="text/plain",
                        part_index=0,
                        part_count=1,
                        content=b"public synthetic tool output",
                    ),
                ),
            )
        result = await self.coordinator.ingest_request(request)
        self.answers.append(
            (envelope.source.value, envelope.event_kind, result.disposition.value, result.reason)
        )
        if result.disposition.value in {"accepted", "duplicate"}:
            self.delivered.append(envelope)
        return result


async def sweep_all(cell: Replay, *, capture_hook_output: bool = False) -> Recorder:
    recorder = Recorder(build_coordinator(cell), capture_hook_output=capture_hook_output)
    sweeper = ObservationOutboxSweeper(cell.store, recorder)
    try:
        for _ in range(8):
            if (await sweeper.sweep()).attempted == 0:
                break
    finally:
        sweeper.close()
    assert cell.store.list_pending_outbox_rows(cell.commitment) == ()
    return recorder


def session_start(cell: Replay, *, cli_version: str = "0.157.1") -> None:
    cell.append(
        rollout_row(
            "session_meta",
            {
                "cli_version": cli_version,
                "cwd": str(cell.workspace),
                "history_mode": "legacy",
                "id": HOST,
                "originator": "codex_exec",
            },
            "2026-09-29T17:54:00.000Z",
        )
    )
    cell.hook("SessionStart", source="startup")


def running_run(cell: Replay, call: str) -> None:
    """A nested exec_command whose process outlives its yield window: the hook states no exit."""

    command = {"command": "cargo test"}
    cell.hook("PreToolUse", tool_name="Bash", tool_use_id=call, tool_input=command)
    cell.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id=call,
        tool_input=command,
        tool_response=json.dumps(
            {
                "chunk_id": call[-6:],
                "original_token_count": 0,
                "output": "public synthetic output",
                "session_id": 3,
                "wall_time_seconds": 10.0,
            }
        ),
    )


def compact(cell: Replay) -> None:
    """A Codex context compaction: ``PreCompact`` then a ``SessionStart`` with source compact.

    The hook generation advances at the compact start; the rollout file is not rotated, so the
    session stream stays in its first generation.
    """

    cell.hook("PreCompact", trigger="auto")
    cell.hook("SessionStart", source="compact")
