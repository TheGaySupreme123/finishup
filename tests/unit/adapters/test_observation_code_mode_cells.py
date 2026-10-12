"""Bounded code-mode cell and orphan-notice bookkeeping stays correct at capacity (#917)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from builders.codex_rollout import encode_lines, response_item, session_meta
from yoetz.adapters.integrations.codex_session_stream import (
    CodexSessionStreamLocator,
    reconcile_session_stream,
)
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationSource,
    ObservationStatusQuery,
)
from yoetz.domain.values import JsonObject, Timestamp


def _store(tmp_path: Path) -> tuple[LocalObservationStore, str]:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    return store, workspace


def _tool_hook(session: str, call: str, kind: str = "PreToolUse") -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=session,
        event_kind=kind,
        source_identity=f"hook:{session[-12:]}:{call}:{kind}",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(1, 0, 1, f"hmac-sha256:{'ab' * 32}", "codex-obs-hook/1.0.0"),
        receipt_time=Timestamp("2026-09-29T17:58:11.363Z"),
        structural_payload=JsonObject({"tool_name": "Bash", "tool_call_id": call}),
        content_object_refs=(),
        gap_codes=(),
    )


def _session(index: int) -> str:
    return f"hmac-sha256:{index:064x}"


def _cell_row(call_id: str, *, output: bool = False) -> dict[str, Any]:
    """One code-mode ``exec`` cell row in the Codex 0.157.1 rollout shape."""

    if output:
        payload: dict[str, Any] = {
            "call_id": call_id,
            "output": [{"text": "Script completed\n", "type": "input_text"}],
            "type": "custom_tool_call_output",
        }
    else:
        payload = {
            "call_id": call_id,
            "input": 'await tools.exec_command({cmd:"true"});\n',
            "name": "exec",
            "status": "completed",
            "type": "custom_tool_call",
        }
    return response_item(payload)


class _Stream:
    """One Codex session whose tool hooks each trigger a reconcile, as the hook path does."""

    def __init__(self, tmp_path: Path, session_id: str = "019f9b27-c1de-7a61-9c5e-5d0b8975941a"):
        self.home = tmp_path / "codex-home"
        (self.home / "sessions").mkdir(parents=True)
        self.home.chmod(0o700)
        self.session_id = session_id
        self.rollout = self.home / "sessions" / f"rollout-{session_id}.jsonl"
        self.rollout.write_bytes(encode_lines(session_meta(session_id=session_id)))
        self.state = tmp_path / "state"
        self.state.mkdir(mode=0o700)
        self.store, self.workspace = _store(self.state)
        self.session = self.store.session_commitment(session_id)
        self.store.bind_session(self.workspace, self.session)

    def reopen(self) -> None:
        self.store = LocalObservationStore(_state=self.state)

    def append(self, *rows: dict[str, Any]) -> None:
        with self.rollout.open("ab") as handle:
            handle.write(encode_lines(*rows))

    def reconcile(self) -> None:
        reconcile_session_stream(
            self.store,
            workspace_commitment=self.workspace,
            session_commitment=self.session,
            codex_session_id=self.session_id,
            locator=CodexSessionStreamLocator(self.home),
        )

    def hook(self, call: str, kind: str = "PreToolUse") -> None:
        self.store.ingest(_tool_hook(self.session, call, kind), workspace_commitment=self.workspace)
        self.reconcile()

    def delivered_cell_rows(self) -> list[tuple[str, str]]:
        return [
            (
                str(row.envelope.structural_payload.get("action")),
                str(row.envelope.structural_payload.get("tool_call_id")),
            )
            for row in self.store.list_pending_outbox_rows(self.workspace)
            if row.envelope.source is ObservationSource.CODEX_SESSION_STREAM
            and row.envelope.structural_payload.get("tool_name") == "exec"
        ]


def _settle(store: LocalObservationStore, workspace: str, session: str) -> None:
    """One complete stream pass that read no new cell row, as each tool hook triggers."""

    store.settle_code_mode_pass(
        workspace, session, store.code_mode_pass_snapshot(workspace, session)
    )


def test_a_new_session_past_the_tracking_bound_keeps_hooked_cells_local(tmp_path: Path) -> None:
    """A full tool-hook map forgets the least recently active session, never the new one."""

    stream = _Stream(tmp_path)
    with stream.store.batched(stream.workspace):
        for index in range(1, 257):
            stream.store.ingest(
                _tool_hook(_session(index), "call-1"), workspace_commitment=stream.workspace
            )
    # The nested tool's hooks fire around the cell, each triggering its own read.
    stream.append(_cell_row("call_cell"))
    stream.hook("call_nested")
    stream.hook("call_nested", "PostToolUse")
    stream.append(_cell_row("call_cell", output=True))
    stream.reconcile()

    assert stream.delivered_cell_rows() == []
    assert stream.store.codex_tool_hook_count(stream.workspace, stream.session) == 2
    # The least recently active session is the one forgotten.
    assert stream.store.codex_tool_hook_count(stream.workspace, _session(1)) == 0
    assert stream.store.codex_tool_hook_count(stream.workspace, _session(2)) == 1


def test_an_evicted_session_reconciled_before_its_nested_hook_keeps_the_cell_local(
    tmp_path: Path,
) -> None:
    """A forgotten hook session never turns its next cell into a second record (#917).

    The session was hooked, then 256 other sessions' tool hooks evicted it from the
    bounded map. A manual reconcile reads its next ``exec`` cell before the nested
    hook is admitted; the nested hooks then arrive and the output is reconciled.
    The nested hook rows are the cell's record, so neither wrapper row is delivered.
    """

    stream = _Stream(tmp_path)
    stream.hook("call_earlier")
    with stream.store.batched(stream.workspace):
        for index in range(1, 257):
            stream.store.ingest(
                _tool_hook(_session(index), "call-1"), workspace_commitment=stream.workspace
            )
    assert stream.store.codex_tool_hook_count(stream.workspace, stream.session) == 0

    # ``yoetz observe reconcile`` reads the cell's call before its nested hook fires.
    stream.append(_cell_row("call_cell"))
    stream.reconcile()
    stream.hook("call_nested")
    stream.hook("call_nested", "PostToolUse")
    stream.append(_cell_row("call_cell", output=True))
    stream.reconcile()
    assert stream.delivered_cell_rows() == []


def test_a_cell_read_before_the_sessions_first_tool_hook_follows_its_own_hooks(
    tmp_path: Path,
) -> None:
    """An early read of a session's first cell is decided by that cell's own hooks."""

    store, workspace = _store(tmp_path)
    session = _session(11)
    store.begin_code_mode_cell(workspace, session, "call_first")
    store.ingest(_tool_hook(session, "call-a"), workspace_commitment=workspace)
    _settle(store, workspace, session)
    assert store.finish_code_mode_cell(workspace, session, "call_first") is True
    # A hook no complete pass has settled may be a later cell's: the output is delivered.
    store.begin_code_mode_cell(workspace, session, "call_second")
    store.ingest(_tool_hook(session, "call-b"), workspace_commitment=workspace)
    assert store.finish_code_mode_cell(workspace, session, "call_second") is False


def test_a_session_forgotten_and_rehooked_while_its_cell_is_open_keeps_the_cell_local(
    tmp_path: Path,
) -> None:
    """Eviction resets a session's hook stamps; a later nested hook still counts for the cell."""

    store, workspace = _store(tmp_path)
    session = _session(12)
    for call in ("call-a", "call-b", "call-c"):
        store.ingest(_tool_hook(session, call), workspace_commitment=workspace)
    _settle(store, workspace, session)
    store.begin_code_mode_cell(workspace, session, "call_open")
    with store.batched(workspace):
        for index in range(1_000, 1_256):
            store.ingest(_tool_hook(_session(index), "call-1"), workspace_commitment=workspace)
    assert store.codex_tool_hook_count(workspace, session) == 0
    store.ingest(_tool_hook(session, "call-nested"), workspace_commitment=workspace)
    _settle(store, workspace, session)
    assert store.finish_code_mode_cell(workspace, session, "call_open") is True


def test_a_cell_is_local_only_when_its_own_nested_tool_hooks_fired(tmp_path: Path) -> None:
    store, workspace = _store(tmp_path)
    session = _session(9)
    # No tool hook has fired in this session yet: a call is still held, and a
    # cell whose tools fire no hook is recorded through its output.
    assert store.begin_code_mode_cell(workspace, session, "call_first") is True
    assert store.finish_code_mode_cell(workspace, session, "call_first") is False

    # A hooked cell: the call is held and the output stays local.
    store.ingest(_tool_hook(session, "call-a"), workspace_commitment=workspace)
    _settle(store, workspace, session)
    assert store.begin_code_mode_cell(workspace, session, "call_hooked") is True
    store.ingest(_tool_hook(session, "call-a", "PostToolUse"), workspace_commitment=workspace)
    _settle(store, workspace, session)
    assert store.finish_code_mode_cell(workspace, session, "call_hooked") is True

    # A later cell whose tools fire no hook is still recorded through its output.
    assert store.begin_code_mode_cell(workspace, session, "call_plan") is True
    assert store.finish_code_mode_cell(workspace, session, "call_plan") is False
    # Decisions replay identically, including after a restart.
    reopened = LocalObservationStore(_state=tmp_path)
    assert reopened.finish_code_mode_cell(workspace, session, "call_hooked") is True
    assert reopened.finish_code_mode_cell(workspace, session, "call_plan") is False
    # An output whose start was never seen stays deliverable.
    assert reopened.finish_code_mode_cell(workspace, session, "call_unknown") is False


def test_an_unhooked_cell_read_early_keeps_its_record_when_the_next_cell_is_hooked(
    tmp_path: Path,
) -> None:
    """A later cell's nested hook never counts as the earlier cell's record (#917).

    In a session with no tool hook yet, a manual reconcile reads unhooked cell A's
    call while A runs. A finishes, the next cell B starts and B's nested hook is
    ingested; the reconcile that hook triggers reads A's output. That hook belongs
    to B, so A's output is delivered and A keeps its record.
    """

    stream = _Stream(tmp_path)
    stream.append(_cell_row("call_cellA"))
    stream.reconcile()
    stream.append(_cell_row("call_cellA", output=True), _cell_row("call_cellB"))
    stream.hook("call_nestedB")

    assert ("custom_tool_call_output", "call_cellA") in stream.delivered_cell_rows()
    # B's own nested hooks then keep B local.
    stream.hook("call_nestedB", "PostToolUse")
    stream.append(_cell_row("call_cellB", output=True))
    stream.reconcile()
    assert [row for row in stream.delivered_cell_rows() if row[1] == "call_cellB"] == []


def test_an_open_cell_stored_before_the_clock_format_is_migrated_not_dropped(
    tmp_path: Path,
) -> None:
    """A held cell persisted in the earlier count format still finishes without a duplicate."""

    stream = _Stream(tmp_path)
    stream.append(_cell_row("call_cellA"))
    stream.hook("call_nestedA")
    path = next((stream.state / "observation" / "workspaces").glob("*.json"))
    document = json.loads(path.read_text(encoding="utf-8"))
    cells = document["code_mode_cells"]
    assert len(cells) == 1
    for entry in cells.values():
        touched = entry["touched"]
        entry.clear()
        entry.update(
            {"hooks_at_start": 1, "pre_withheld": True, "output_local": None, "touched": touched}
        )
    path.write_text(json.dumps(document), encoding="utf-8")
    stream.reopen()

    stream.hook("call_nestedA", "PostToolUse")
    stream.append(_cell_row("call_cellA", output=True))
    stream.reconcile()
    assert stream.delivered_cell_rows() == []


def test_delivered_notices_do_not_exhaust_new_scope_notices(tmp_path: Path) -> None:
    store, workspace = _store(tmp_path)
    session = _session(3)
    with store.batched(workspace):
        for generation in range(1, 257):
            store.note_unpaired_event(
                workspace,
                source=ObservationSource.CODEX_HOOK,
                session_commitment=session,
                source_generation=generation,
                source_identity=f"hook:orphan-{generation}",
            )
            notice = store.peek_unpaired_notice(workspace, session)
            assert notice is not None and notice.source_generation == generation
            store.commit_unpaired_notice_delivery(workspace, notice.lane)
    store.note_unpaired_event(
        workspace,
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=257,
        source_identity="hook:orphan-257",
    )
    fresh = store.peek_unpaired_notice(workspace, session)
    assert fresh is not None and fresh.source_generation == 257
    store.commit_unpaired_notice_delivery(workspace, fresh.lane)
    # A recently announced scope is still never announced again.
    store.note_unpaired_event(
        workspace,
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=256,
        source_identity="hook:orphan-256-again",
    )
    assert store.peek_unpaired_notice(workspace, session) is None


def test_a_delivered_scope_repeats_only_after_leaving_the_retained_window(
    tmp_path: Path,
) -> None:
    """The notice map's bound is the documented one.

    A delivered scope is not announced again while the 256-scope map retains it.
    Once newer scopes push it out, its next orphan announces it again, after which
    it is retained again; further churn can push it out, and repeat it, again.
    """

    store, workspace = _store(tmp_path)
    session = _session(4)

    def orphan(generation: int, tag: str) -> None:
        store.note_unpaired_event(
            workspace,
            source=ObservationSource.CODEX_HOOK,
            session_commitment=session,
            source_generation=generation,
            source_identity=f"hook:orphan-{generation}-{tag}",
        )

    with store.batched(workspace):
        for generation in range(1, 258):
            orphan(generation, "first")
            notice = store.peek_unpaired_notice(workspace, session)
            assert notice is not None and notice.source_generation == generation
            store.commit_unpaired_notice_delivery(workspace, notice.lane)
    # Scope 1 was the oldest delivered notice, forgotten to admit scope 257.
    orphan(1, "again")
    repeated = store.peek_unpaired_notice(workspace, session)
    assert repeated is not None and repeated.source_generation == 1
    store.commit_unpaired_notice_delivery(workspace, repeated.lane)
    # Retained again, it is not announced again until newer scopes push it out.
    orphan(1, "third")
    assert store.peek_unpaired_notice(workspace, session) is None
    # The aggregate gap stays disclosed throughout.
    gaps = store.status(ObservationStatusQuery(workspace)).gaps
    assert ObservationGapCode.UNPAIRED_EVENT.value in gaps


def test_a_cell_whose_nested_items_are_all_yoetz_calls_stays_local(tmp_path: Path) -> None:
    """#1038: Yoetz-only cells stay local whatever the hook timing; the mark is never borrowed."""

    store, workspace = _store(tmp_path)
    session = _session(21)
    # No tool hook fired, so the #917 rule alone would deliver every output.
    assert store.begin_code_mode_cell(workspace, session, "call_own") is True
    store.note_code_mode_nested_item(workspace, session, yoetz_owned=True)
    assert store.finish_code_mode_cell(workspace, session, "call_own") is True
    # One other nested item keeps the cell's own record.
    store.begin_code_mode_cell(workspace, session, "call_mixed")
    store.note_code_mode_nested_item(workspace, session, yoetz_owned=True)
    store.note_code_mode_nested_item(workspace, session, yoetz_owned=False)
    assert store.finish_code_mode_cell(workspace, session, "call_mixed") is False
    # A cell with no nested item at all keeps its record too.
    store.begin_code_mode_cell(workspace, session, "call_empty")
    assert store.finish_code_mode_cell(workspace, session, "call_empty") is False
    # With two cells open a Yoetz item cannot be attributed: neither takes the mark.
    store.begin_code_mode_cell(workspace, session, "call_a")
    store.begin_code_mode_cell(workspace, session, "call_b")
    store.note_code_mode_nested_item(workspace, session, yoetz_owned=True)
    assert store.finish_code_mode_cell(workspace, session, "call_a") is False
    assert store.finish_code_mode_cell(workspace, session, "call_b") is False
    # Another session's items never mark this session's cells.
    store.begin_code_mode_cell(workspace, session, "call_alone")
    store.note_code_mode_nested_item(workspace, _session(22), yoetz_owned=False)
    store.note_code_mode_nested_item(workspace, session, yoetz_owned=True)
    # The marks and decisions are durable across a restart.
    reopened = LocalObservationStore(_state=tmp_path)
    assert reopened.finish_code_mode_cell(workspace, session, "call_alone") is True
    assert reopened.finish_code_mode_cell(workspace, session, "call_own") is True
    assert reopened.finish_code_mode_cell(workspace, session, "call_mixed") is False
