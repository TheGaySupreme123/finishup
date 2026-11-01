"""Shared observation-store contention: ownership facts, bounded waits, committed reads (#689).

Every synchronization point here is observed state: a holder process reports that it holds the
lock on stdout before the waiter starts, an in-process owner sets an event, and a timed-out waiter
reports the holder it queued behind. No test infers success from a sleep.
"""

from __future__ import annotations

import contextlib
import subprocess
import sys
import threading
import time
from collections.abc import Generator
from pathlib import Path
from typing import cast

import pytest

import finishup.adapters.integrations.observation_local as local
from finishup.adapters.integrations.observation_local import (
    LocalObservationStore,
    ObservationOutboxRow,
    ObservationStoreLockEvent,
    ObservationStoreLockTimeout,
    observation_store_lock_deadline,
    observation_store_lock_scope,
)
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationSource,
    ObservationStatusQuery,
    observation_envelope_to_json,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.canonical import canonical_encode

pytestmark = pytest.mark.skipif(local.fcntl is None, reason="POSIX flock is unavailable")

_HOLDER = """
import sys
from pathlib import Path
from finishup.adapters.integrations.observation_local import (
    LocalObservationStore,
    set_observation_store_lock_role,
)

set_observation_store_lock_role("hook")
store = LocalObservationStore(_state=Path(sys.argv[1]))
workspace = sys.argv[2]


def hold_for_contention_test():
    with store.batched(workspace):
        state = store._load(workspace)
        state.last_hook_receipt_mono_ms = 424242
        store._save(workspace, state)
        print("held", flush=True)
        sys.stdin.readline()


hold_for_contention_test()
print("released", flush=True)
"""


def _envelope(session: str, ordinal: int) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=session,
        event_kind="PostToolUse",
        source_identity=f"hook:contention:{ordinal}",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(1, 0, ordinal, f"hmac-sha256:{'ab' * 32}", "codex-obs-hook/1.0.0"),
        receipt_time=Timestamp("2026-01-01T00:00:00.000Z"),
        structural_payload=JsonObject({"tool_name": "shell", "tool_call_id": f"c{ordinal}"}),
        content_object_refs=(),
        gap_codes=(),
    )


def _store(tmp_path: Path) -> tuple[LocalObservationStore, str, str]:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "sess-contention")
    return store, workspace, session


@contextlib.contextmanager
def _holder_process(tmp_path: Path, workspace: str) -> Generator[subprocess.Popen[str]]:
    """Run a separate process that holds the store lock inside an open batch."""

    process = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, str(tmp_path), workspace],
        cwd=tmp_path,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin is not None and process.stdout is not None
    try:
        assert process.stdout.readline().strip() == "held"
        yield process
    finally:
        with contextlib.suppress(BrokenPipeError):
            process.stdin.write("\n")
            process.stdin.flush()
        assert process.stdout.readline().strip() == "released"
        _stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stderr


@pytest.fixture
def events() -> Generator[list[ObservationStoreLockEvent]]:
    recorded: list[ObservationStoreLockEvent] = []
    previous = local.set_observation_store_lock_reporter(recorded.append)
    try:
        yield recorded
    finally:
        local.set_observation_store_lock_reporter(previous)


def test_cross_process_timeout_names_the_holder_and_reads_never_queue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    events: list[ObservationStoreLockEvent],
) -> None:
    store, workspace, _session = _store(tmp_path)
    monkeypatch.setattr(local, "_STORE_LOCK_TIMEOUT_SECONDS", 0.2)
    with _holder_process(tmp_path, workspace):
        with pytest.raises(ObservationStoreLockTimeout) as raised:
            store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)
        timeout = raised.value
        assert str(timeout) == "observation_store_lock_timeout"
        assert timeout.scope == "process"
        assert timeout.holder_role == "hook"
        assert timeout.holder_phase == "hold_for_contention_test"
        assert timeout.holder_held_ms is not None and timeout.holder_held_ms >= 0
        assert timeout.holder_waiting is False
        # The waiter's own phase and the holder facts reach the process reporter once.
        assert [(event.kind, event.phase, event.timeout) for event in events] == [
            ("timeout", "note_coverage_gap", timeout)
        ]

        # Reads observe the committed document without queueing behind the holder, and never
        # its uncommitted transaction.
        assert store.consent_for(workspace) is not None
        assert store.pending_outbox_count(workspace) == 0
        assert store.status(ObservationStatusQuery(workspace)).workspace_commitment == workspace
        assert (
            local.LocalObservationStore(_state=tmp_path).workspace_commitment(
                str(tmp_path.resolve())
            )
            == workspace
        )
        assert store._load(workspace).last_hook_receipt_mono_ms != 424242  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    # Released: the holder's commit is visible and the same write now succeeds.
    assert store._load(workspace).last_hook_receipt_mono_ms == 424242  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)
    assert (
        ObservationGapCode.SERVICE_UNAVAILABLE.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )


def test_deadline_scope_bounds_every_wait_below_the_acquisition_cap(
    tmp_path: Path, events: list[ObservationStoreLockEvent]
) -> None:
    del events
    store, workspace, _session = _store(tmp_path)
    with _holder_process(tmp_path, workspace):
        with observation_store_lock_deadline(time.monotonic() + 0.05):
            with pytest.raises(ObservationStoreLockTimeout) as raised:
                store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)
            assert local.observation_store_lock_remaining() is not None
        # The two-second cap would have allowed far longer; the scope ended the wait.
        assert raised.value.waited_ms < 1_000
        # A spent deadline still allows exactly one nonblocking attempt, and nests earlier-wins.
        with observation_store_lock_deadline(time.monotonic() - 1.0):
            with observation_store_lock_deadline(time.monotonic() + 60.0):
                with pytest.raises(ObservationStoreLockTimeout) as spent:
                    store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)
        assert spent.value.waited_ms < 1_000
    assert local.observation_store_lock_remaining() is None


def test_thread_timeout_names_the_in_process_owner_and_its_batch_stays_private(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    events: list[ObservationStoreLockEvent],
) -> None:
    store, workspace, session = _store(tmp_path)
    monkeypatch.setattr(local, "_STORE_LOCK_TIMEOUT_SECONDS", 0.2)
    holding = threading.Event()
    release = threading.Event()
    failures: list[BaseException] = []

    def hold_in_owner_thread() -> None:
        try:
            with observation_store_lock_scope(role="sweep"):
                with store.batched(workspace):
                    store.enqueue_outbox(workspace, "sess-contention", _envelope(session, 1))
                    holding.set()
                    assert release.wait(timeout=30)
        except BaseException as error:  # pragma: no cover - surfaced below
            failures.append(error)
            holding.set()

    owner = threading.Thread(target=hold_in_owner_thread)
    owner.start()
    try:
        assert holding.wait(timeout=30)
        assert not failures
        # The same store instance, another thread: the owner's open batch is invisible.
        assert store.pending_outbox_count(workspace) == 0
        assert store.list_pending_outbox_rows(workspace) == ()
        with pytest.raises(ObservationStoreLockTimeout) as raised:
            store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)
        timeout = raised.value
        assert timeout.scope == "thread"
        assert timeout.holder_role == "sweep"
        assert timeout.holder_phase == "hold_in_owner_thread"
        assert timeout.holder_waiting is False
        assert timeout.holder_held_ms is not None
        assert [event.kind for event in events] == ["timeout"]
    finally:
        release.set()
        owner.join(timeout=30)
    assert not failures
    assert store.pending_outbox_count(workspace) == 1


def test_long_holds_are_reported_after_release_with_their_phase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    events: list[ObservationStoreLockEvent],
) -> None:
    store, workspace, _session = _store(tmp_path)
    monkeypatch.setattr(local, "_STORE_LOCK_LONG_HOLD_SECONDS", 0.0)
    before = store.stage_timings_ms["lock_hold"]
    store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)
    assert [(event.kind, event.phase) for event in events] == [("long_hold", "note_coverage_gap")]
    assert events[0].held_ms is not None and events[0].held_ms >= 0
    assert store.stage_timings_ms["lock_hold"] > before
    # A lock event raised inside a reporter can never fail the store operation.
    local.set_observation_store_lock_reporter(lambda _event: (_ for _ in ()).throw(OSError()))
    store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)


def test_interrupted_preparation_releases_the_thread_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, workspace, _session = _store(tmp_path)
    monkeypatch.setattr(local, "_STORE_LOCK_TIMEOUT_SECONDS", 0.2)

    def interrupt(_workspace: str) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(store, "_prewarm", interrupt)
    with pytest.raises(KeyboardInterrupt):
        with store.batched(workspace):
            pytest.fail("interrupted preparation must not enter the transaction")

    failures: list[BaseException] = []

    def write_after_interruption() -> None:
        try:
            store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=write_after_interruption)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert not failures
    assert (
        ObservationGapCode.SERVICE_UNAVAILABLE.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )


def test_thread_scope_reporter_and_role_override_and_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    events: list[ObservationStoreLockEvent],
) -> None:
    store, workspace, _session = _store(tmp_path)
    monkeypatch.setattr(local, "_STORE_LOCK_LONG_HOLD_SECONDS", 0.0)
    scoped: list[ObservationStoreLockEvent] = []
    with observation_store_lock_scope(role="hook", reporter=scoped.append):
        store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)
    store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)
    assert [event.role for event in scoped] == ["hook"]
    assert len(events) == 1 and events[0].role != "hook"
    with pytest.raises(ValueError, match="observation_store_lock_role_invalid"):
        with observation_store_lock_scope(role="not-a-role"):
            pass


def test_read_mostly_method_escalates_to_the_lock_for_its_write(tmp_path: Path) -> None:
    """A committed read that must repair legacy state reruns under the lock and persists it."""

    store, workspace, _session = _store(tmp_path)
    with store._lock:  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        state = store._load(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        state.content_capture_epoch = None
        # Encoding re-creates a missing epoch, so strip it from the bytes directly.
        store._save(workspace, state)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    path = store._workspace_path(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    import json

    document = json.loads(path.read_text(encoding="utf-8"))
    document.pop("content_capture_epoch", None)
    path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    path.chmod(0o600)

    fresh = LocalObservationStore(_state=tmp_path)
    first = fresh.content_capture_authority(workspace)
    assert first is not None
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert type(persisted.get("content_capture_epoch")) is str
    second = LocalObservationStore(_state=tmp_path).content_capture_authority(workspace)
    assert second is not None and second.generation == first.generation
    assert fresh.content_capture_authority_is_current(workspace, first.generation, first.profiles)


def test_a_pure_read_that_writes_fails_loudly_instead_of_writing_unlocked(
    tmp_path: Path,
) -> None:
    store, workspace, _session = _store(tmp_path)
    with store._reading():  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        state = store._load(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        with pytest.raises(local._LockedWriteRequired):  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            store._save(workspace, state)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def _inline_encoding(
    store: LocalObservationStore,
    workspace: str,
    state: local._WorkspaceState,  # pyright: ignore[reportPrivateUsage]
) -> bytes:
    """Encode a state the pre-#689 way: every member rebuilt and encoded inline."""

    assert state.envelopes is not None and state.quarantine is not None
    tree = store._state_to_json(workspace, state)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    tree["envelopes"] = tuple(observation_envelope_to_json(item) for item in state.envelopes)
    tree["pending_outbox"] = tuple(
        local._outbox_row_to_json(row)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        for row in state.pending_outbox or ()
    )
    tree["quarantine"] = tuple(
        JsonObject(
            {
                "codex_session_id": entry[0],
                "envelope": observation_envelope_to_json(entry[1]),
                "reason": entry[2],
                "quarantined_at": entry[3].wire,
            }
        )
        for entry in state.quarantine
    )
    return canonical_encode(tree) + b"\n"


def test_spliced_state_encoding_is_byte_identical_to_inline_encoding(tmp_path: Path) -> None:
    store, workspace, session = _store(tmp_path)
    for ordinal in range(1, 41):
        store.enqueue_outbox(workspace, "sess-contention", _envelope(session, ordinal))
    rows = store.list_pending_outbox_rows(workspace)
    bumped = store.bump_outbox_row_attempt(workspace, rows[0], reason="service_unavailable")
    assert bumped is not None
    assert store.quarantine_outbox_row(workspace, bumped, "service_unavailable")
    fresh = LocalObservationStore(_state=tmp_path)
    state = fresh._load(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert state.quarantine and state.pending_outbox and state.envelopes is not None
    spliced = fresh._encode_state(workspace, state)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert spliced == _inline_encoding(fresh, workspace, state)
    # Size projections agree with inline encoding too.
    row = state.pending_outbox[0]
    assert local._outbox_row_bytes(row) == len(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        canonical_encode(local._outbox_row_to_json(row))  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    )
    assert local._delivery_unit_bytes(row.codex_session_id, row.envelope) == len(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        canonical_encode(
            JsonObject(
                {
                    "codex_session_id": row.codex_session_id,
                    "envelope": observation_envelope_to_json(row.envelope),
                }
            )
        )
    )


def test_reparse_after_another_writer_reuses_unchanged_envelopes_exactly(
    tmp_path: Path,
) -> None:
    store, workspace, session = _store(tmp_path)
    for ordinal in range(1, 6):
        store.enqueue_outbox(workspace, "sess-contention", _envelope(session, ordinal))
    reader = LocalObservationStore(_state=tmp_path)
    before = reader.list_pending_outbox_rows(workspace)
    writer = LocalObservationStore(_state=tmp_path)
    changed = writer.bump_outbox_row_attempt(
        workspace, writer.list_pending_outbox_rows(workspace)[0], reason="service_unavailable"
    )
    assert changed is not None
    after = reader.list_pending_outbox_rows(workspace)
    # The attempt count changed only the row; every envelope is the same validated object.
    assert [row.envelope for row in after] == [row.envelope for row in before]
    assert all(new.envelope is old.envelope for new, old in zip(after, before, strict=True))
    assert after[0].attempts == before[0].attempts + 1
    # A genuinely different envelope decodes to a different object with its own value.
    other = _envelope(session, 99)
    writer.enqueue_outbox(workspace, "sess-contention", other)
    decoded = reader.list_pending_outbox_rows(workspace)[-1].envelope
    assert decoded == other
    assert all(decoded is not row.envelope for row in before)


def test_committed_rows_are_immutable_members_the_codec_can_key_by_identity() -> None:
    row = ObservationOutboxRow("sess", _envelope(f"hmac-sha256:{'cd' * 32}", 1))
    with pytest.raises(AttributeError):
        cast(object, row).__setattr__("attempts", 3)
    first = local._outbox_row_fragment(row)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert local._outbox_row_fragment(row) is first  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def test_a_holder_killed_mid_transaction_frees_the_store_and_commits_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """flock dies with its process: no stale owner, no partial write, next writer proceeds."""

    store, workspace, _session = _store(tmp_path)
    monkeypatch.setattr(local, "_STORE_LOCK_TIMEOUT_SECONDS", 5.0)
    path = store._workspace_path(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    committed = path.read_bytes()
    process = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, str(tmp_path), workspace],
        cwd=tmp_path,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    try:
        assert process.stdout.readline().strip() == "held"
        # The holder stamped its ownership while it held the lock.
        stamp = (tmp_path / "observation" / ".store.lock").read_text(encoding="ascii")
        assert '"phase":"hold_for_contention_test"' in stamp
    finally:
        process.kill()
        process.communicate(timeout=30)
    # Its open transaction never reached the document.
    assert path.read_bytes() == committed
    store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)
    assert (
        ObservationGapCode.SERVICE_UNAVAILABLE.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )
    assert store._load(workspace).last_hook_receipt_mono_ms != 424242  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    # Our own release cleared the stamp, so a later waiter can never blame the dead holder.
    assert (tmp_path / "observation" / ".store.lock").read_bytes() == b""


def _document(tmp_path: Path) -> tuple[LocalObservationStore, str, Path, dict[str, object]]:
    import json

    store, workspace, session = _store(tmp_path)
    for ordinal in range(1, 4):
        store.enqueue_outbox(workspace, "sess-contention", _envelope(session, ordinal))
    rows = store.list_pending_outbox_rows(workspace)
    bumped = store.bump_outbox_row_attempt(workspace, rows[0], reason="service_unavailable")
    assert bumped is not None
    assert store.quarantine_outbox_row(workspace, bumped, "service_unavailable")
    path = store._workspace_path(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    return store, workspace, path, json.loads(path.read_text(encoding="utf-8"))


def _tampered(document: dict[str, object], where: str) -> dict[str, object]:
    import copy

    tampered = copy.deepcopy(document)
    nul = "bad\x00value"
    pending = cast(list[dict[str, object]], tampered["pending_outbox"])
    quarantine = cast(list[dict[str, object]], tampered["quarantine"])
    envelope = cast(dict[str, object], pending[0]["envelope"])
    if where == "top_level":
        tampered["advice_frontier"] = nul
    elif where == "row_field":
        pending[0]["last_reason"] = nul
    elif where == "row_envelope":
        cast(dict[str, object], envelope["structural_payload"])["tool_name"] = nul
    elif where == "quarantine_envelope":
        quarantine_envelope = cast(dict[str, object], quarantine[0]["envelope"])
        cast(dict[str, object], quarantine_envelope["structural_payload"])["tool_name"] = nul
    elif where == "key":
        tampered["bad\x00key"] = 1
    elif where == "nesting":
        deep: object = 0
        for _ in range(64):
            deep = [deep]
        tampered["read_protections"] = deep
    return tampered


@pytest.mark.parametrize(
    "where",
    ("top_level", "row_field", "row_envelope", "quarantine_envelope", "key", "nesting"),
)
def test_member_validation_rejects_exactly_what_whole_validation_rejects(
    tmp_path: Path, where: str
) -> None:
    """#689: skipping already-validated envelopes never admits an invalid document."""

    import json

    from finishup.protocol.canonical import ensure_canonical_value, strict_json_parse
    from finishup.protocol.errors import ProtocolValueError

    store, workspace, path, document = _document(tmp_path)
    # Warm the process's envelope memo with the valid document first.
    assert store.list_pending_outbox_rows(workspace)
    raw = json.dumps(_tampered(document, where), sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ProtocolValueError):
        ensure_canonical_value(strict_json_parse(raw, validate=False))
    with pytest.raises(ProtocolValueError):
        local._validate_state_document(strict_json_parse(raw, validate=False))  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    # The store treats the tampered document exactly as before: an unreadable, empty state.
    path.write_bytes(raw + b"\n")
    path.chmod(0o600)
    fresh = LocalObservationStore(_state=tmp_path)
    assert fresh.pending_outbox_count(workspace) == 0
    assert fresh.consent_for(workspace) is None


def test_member_validation_accepts_the_valid_document_and_reuses_envelopes(
    tmp_path: Path,
) -> None:
    from finishup.protocol.canonical import strict_json_parse

    store, workspace, path, _document_value = _document(tmp_path)
    # Decoded from the committed file (the writer's own cache holds its original objects).
    before = LocalObservationStore(_state=tmp_path).list_pending_outbox_rows(workspace)
    parsed = strict_json_parse(path.read_bytes(), validate=False)
    keys = local._validate_state_document(parsed)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    # Every retained, pending and quarantined envelope got its decode key once.
    assert len(keys) == len(store._load(workspace).envelopes or ()) + len(before) + 1  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    after = LocalObservationStore(_state=tmp_path).list_pending_outbox_rows(workspace)
    assert all(new.envelope is old.envelope for new, old in zip(after, before, strict=True))
