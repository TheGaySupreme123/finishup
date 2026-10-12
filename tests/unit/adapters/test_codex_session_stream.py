"""Unit tests for incremental Codex session-stream observation."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from builders.codex_rollout import (
    completed_shell_rollout,
    encode_lines,
    failed_shell_rollout,
    function_call,
    function_call_output,
    item_completed,
    response_item,
    session_meta,
)
from builders.shell_write_vectors import VECTORS, ShellWriteVector
from yoetz.adapters.importers.codex_jsonl import CodexParsedRecord
from yoetz.adapters.importers.codex_rollout_jsonl import ROLLOUT_MAX_LINE_BYTES
from yoetz.adapters.integrations import codex_session_stream as stream_module
from yoetz.adapters.integrations.codex_lifecycle import mapping_from_start_ids, store_mapping
from yoetz.adapters.integrations.codex_session_stream import (
    CodexSessionStreamLocator,
    SessionStreamReader,
    default_stream_profile,
    envelope_from_stream_record,
    reconcile_session_stream,
    should_trigger_stream_reconcile,
    stream_profile_from_id,
)
from yoetz.adapters.integrations.observation_admission import AdmissionPlan
from yoetz.adapters.integrations.observation_local import (
    STREAM_MAPPING_VERSION,
    LocalObservationStore,
)
from yoetz.application.observation_materialize import materialize_observation_envelope
from yoetz.domain.events import ResultOutcome, ResultRecordedPayload
from yoetz.domain.host_lineage import host_lineage_from_envelope
from yoetz.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestResult,
    ObservationSource,
    ObservationStatusQuery,
)
from yoetz.domain.observation_budget import AdmissionLossCause, ObservationMode
from yoetz.domain.values import JsonObject, Timestamp


def test_source_file_identity_bounds_large_filesystem_integers() -> None:
    facts = cast(
        os.stat_result,
        SimpleNamespace(st_dev=1 << 63, st_ino=(1 << 63) + 1),
    )

    identity = stream_module._source_file_identity(  # pyright: ignore[reportPrivateUsage]
        facts,
        b"k" * 32,
    )

    assert identity.startswith("hmac-sha256:")
    assert len(identity) == len("hmac-sha256:") + 64


_EMPTY = "hmac-sha256:" + ("0" * 64)
_KEY = b"k" * 32


def _reader(session: str, *, generation: int = 1) -> SessionStreamReader:
    return SessionStreamReader(
        session_commitment=session,
        profile=default_stream_profile(),
        cursor=ObservationCursor(
            source_generation=generation,
            byte_position=0,
            event_position=0,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
        key_material=_KEY,
    )


def test_default_stream_profile_is_rollout_0_148() -> None:
    profile = default_stream_profile()
    assert profile.cli_version == "0.148.0"
    assert profile.profile_id == "codex-rollout-jsonl/0.148.0/v1"


def test_incremental_partial_line_then_complete(tmp_path: Path) -> None:
    path = tmp_path / "session.jsonl"
    first = encode_lines(session_meta(), terminated=False)
    path.write_bytes(first)
    session = "hmac-sha256:" + ("b" * 64)
    reader = _reader(session)
    advance = reader.advance(path)
    assert advance.envelopes == ()
    assert advance.partial_line.startswith(b'{"payload":')
    # A tail Codex is still writing is held, not truncated (#1041): complete JSON without its
    # newline, and a line cut mid-object, both wait for the next read.
    assert ObservationGapCode.TRUNCATED_PAYLOAD.value not in advance.gaps
    cut = tmp_path / "cut.jsonl"
    cut.write_bytes(first[:-7])
    held = _reader(session).advance(cut)
    assert held.partial_line == first[:-7]
    assert ObservationGapCode.TRUNCATED_PAYLOAD.value not in held.gaps
    path.write_bytes(first + b"\n")
    advance2 = reader.advance(path)
    assert len(advance2.envelopes) == 1
    assert advance2.envelopes[0].source is ObservationSource.CODEX_SESSION_STREAM
    assert advance2.partial_line == b""
    assert advance2.cursor.last_source_commitment.startswith("hmac-sha256:")
    assert advance2.cursor.last_source_commitment != _EMPTY
    assert ObservationGapCode.UNSUPPORTED_EVENT.value not in advance2.gaps


def test_a_held_tail_unchanged_across_a_read_is_reported_and_still_delivered(
    tmp_path: Path,
) -> None:
    """#1041: a tail no byte reached since the last read is a stopped writer's, not a live one's.

    The first read that holds a tail reports nothing; a later read that finds the same bytes
    held, with nothing written since, names it ``truncated_payload`` so a writer killed mid-line
    is not a silent loss. A tail still growing stays silent, and a late newline still delivers it.
    """

    path = tmp_path / "session.jsonl"
    header = encode_lines(session_meta())
    tail = encode_lines(
        response_item(
            {
                "content": [{"text": "later", "type": "output_text"}],
                "role": "assistant",
                "type": "message",
            }
        ),
        terminated=False,
    )
    path.write_bytes(header + tail[:40])
    reader = _reader("hmac-sha256:" + ("e" * 64))
    first = reader.advance(path)
    assert len(first.envelopes) == 1
    assert first.partial_line == tail[:40]
    assert ObservationGapCode.TRUNCATED_PAYLOAD.value not in first.gaps
    # Codex is still writing: the tail grew, so it is held silently again.
    path.write_bytes(header + tail)
    grown = reader.advance(path)
    assert grown.partial_line == tail
    assert ObservationGapCode.TRUNCATED_PAYLOAD.value not in grown.gaps
    # Nothing reached the file since: the writer stopped mid-line.
    stalled = reader.advance(path)
    assert stalled.envelopes == ()
    assert stalled.partial_line == tail
    assert stalled.cursor == grown.cursor
    assert ObservationGapCode.TRUNCATED_PAYLOAD.value in stalled.gaps
    # The tail stays held: a newline that does land delivers the row with no gap.
    path.write_bytes(header + tail + b"\n")
    landed = reader.advance(path)
    assert len(landed.envelopes) == 1
    assert landed.partial_line == b""
    assert landed.gaps == ()


def test_reconcile_reports_a_held_tail_its_previous_pass_already_held(tmp_path: Path) -> None:
    """#1041: the held tail persists between passes, so the reconcile result names a stalled one."""

    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    session_id = "stream-stalled-tail"
    target = sessions / f"rollout-{session_id}.jsonl"
    complete = encode_lines(session_meta(), function_call(name="shell", call_id="call-tail"))
    tail = b'{"type":"event_msg","payload":{"type":"item_completed","item":{"type":"FileChange"'
    target.write_bytes(complete + tail)
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)

    def reconcile() -> dict[str, Any]:
        return reconcile_session_stream(
            store,
            workspace_commitment=workspace,
            session_commitment=session,
            codex_session_id=session_id,
            locator=CodexSessionStreamLocator(home),
        )

    first = reconcile()
    assert first["accepted"] == 2
    assert ObservationGapCode.TRUNCATED_PAYLOAD.value not in cast(tuple[str, ...], first["gaps"])
    again = reconcile()
    assert again["accepted"] == 0
    assert ObservationGapCode.TRUNCATED_PAYLOAD.value in cast(tuple[str, ...], again["gaps"])
    assert store.get_stream_partial(workspace, session) == tail


def test_incremental_partial_header_still_requires_exact_profile_admission(
    tmp_path: Path,
) -> None:
    """A partial header admits nothing; a structurally refused header stays refused (#656)."""

    path = tmp_path / "session.jsonl"
    # An unknown ``history_mode`` is the structural refusal; the release label alone no longer
    # refuses a header.
    first = encode_lines(
        session_meta(cli_version="0.149.1", history_mode="streamed"), terminated=False
    )
    path.write_bytes(first)
    session = "hmac-sha256:" + ("f" * 64)
    reader = _reader(session)

    advance = reader.advance(path)
    assert advance.envelopes == ()
    assert advance.cursor.byte_position == 0
    assert advance.cursor.event_position == 0
    assert advance.partial_line == first

    path.write_bytes(first + b"\n")
    completed = reader.advance(path)
    assert completed.envelopes == ()
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value in completed.gaps
    assert completed.cursor.byte_position == len(first) + 1
    assert completed.cursor.event_position == 0

    # A rejected header keeps admission durably required: later appends are
    # refused instead of being materialized without an accepted exact profile.
    path.write_bytes(
        first
        + b"\n"
        + encode_lines(
            response_item(
                {
                    "content": [{"text": "later", "type": "output_text"}],
                    "role": "assistant",
                    "type": "message",
                }
            )
        )
    )
    appended = reader.advance(path)
    assert appended.envelopes == ()
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value in appended.gaps
    assert appended.cursor.event_position == 0


def test_completed_oversized_line_advances_and_later_records_remain_reachable(
    tmp_path: Path,
) -> None:
    path = tmp_path / "session.jsonl"
    profile = default_stream_profile()
    chunk = stream_module._MAX_READ_CHUNK  # pyright: ignore[reportPrivateUsage]
    header = encode_lines(session_meta())
    oversized_body = (
        b'{"type":"response_item","payload":"'
        + (b"x" * (profile.max_line_bytes + (2 * chunk)))
        + b'"}'
    )
    later = encode_lines(
        response_item(
            {
                "content": [{"text": "later", "type": "output_text"}],
                "role": "assistant",
                "type": "message",
            }
        )
    )
    path.write_bytes(header + oversized_body + b"\n" + later)
    session = "hmac-sha256:" + ("9" * 64)
    reader = _reader(session)

    admitted = reader.advance(path)
    assert admitted.cursor.event_position == 1
    assert admitted.partial_line

    entered = reader.advance(path)
    assert entered.cursor.event_position == 1
    assert entered.cursor.byte_position == len(header) + profile.max_line_bytes + 1
    assert entered.partial_line.startswith(
        stream_module._OVERSIZED_PARTIAL_PREFIX  # pyright: ignore[reportPrivateUsage]
    )

    cursor = entered.cursor
    partial = entered.partial_line
    skipped = entered
    for _ in range(4):
        prior_position = cursor.byte_position
        skipped = SessionStreamReader(
            session_commitment=session,
            profile=profile,
            cursor=cursor,
            key_material=_KEY,
            partial_line=partial,
        ).advance(path)
        assert skipped.cursor.byte_position - prior_position <= chunk
        cursor = skipped.cursor
        partial = skipped.partial_line
        if skipped.cursor.event_position == 2:
            break

    assert skipped.cursor.event_position == 2
    assert skipped.cursor.byte_position == len(header) + len(oversized_body) + 1
    assert skipped.cursor.last_source_commitment.startswith("hmac-sha256:")
    assert skipped.partial_line == b""
    assert len(skipped.envelopes) == 1
    assert skipped.envelopes[0].event_kind == "unsupported_event"
    assert ObservationGapCode.UNSUPPORTED_EVENT.value in skipped.gaps

    recovered = SessionStreamReader(
        session_commitment=session,
        profile=profile,
        cursor=skipped.cursor,
        key_material=_KEY,
        partial_line=skipped.partial_line,
    ).advance(path)
    assert recovered.cursor.event_position == 3
    assert recovered.cursor.byte_position == path.stat().st_size
    assert len(recovered.envelopes) == 1
    assert recovered.envelopes[0].event_kind == "response_item"


def test_forged_oversized_line_continuation_restarts_from_admission(tmp_path: Path) -> None:
    path = tmp_path / "session.jsonl"
    profile = default_stream_profile()
    header = encode_lines(session_meta())
    oversized_body = (
        b'{"type":"response_item","payload":"' + (b"x" * (profile.max_line_bytes + 10)) + b'"}\n'
    )
    path.write_bytes(header + oversized_body)
    session = "hmac-sha256:" + ("8" * 64)
    reader = _reader(session)

    admitted = reader.advance(path)
    entered = reader.advance(path)
    assert admitted.cursor.event_position == 1
    assert entered.partial_line.startswith(
        stream_module._OVERSIZED_PARTIAL_PREFIX  # pyright: ignore[reportPrivateUsage]
    )
    forged = entered.partial_line[:-1] + bytes([entered.partial_line[-1] ^ 1])

    restarted = SessionStreamReader(
        session_commitment=session,
        profile=profile,
        cursor=entered.cursor,
        key_material=_KEY,
        partial_line=forged,
    ).advance(path)

    assert restarted.cursor.source_generation == entered.cursor.source_generation + 1
    assert restarted.cursor.event_position == 1
    assert ObservationGapCode.CURSOR_STALE.value in restarted.gaps
    assert ObservationGapCode.TRUNCATED_PAYLOAD.value in restarted.gaps
    assert not restarted.partial_line.startswith(
        stream_module._OVERSIZED_PARTIAL_PREFIX  # pyright: ignore[reportPrivateUsage]
    )


def test_oversized_initial_header_never_establishes_profile_admission(tmp_path: Path) -> None:
    path = tmp_path / "session.jsonl"
    profile = default_stream_profile()
    path.write_bytes(b"{" + (b"x" * (profile.max_line_bytes + 10)) + b"}\n")
    session = "hmac-sha256:" + ("7" * 64)
    advance = _reader(session).advance(path)
    assert advance.cursor.event_position == 0
    assert advance.partial_line.startswith(
        stream_module._OVERSIZED_PARTIAL_PREFIX  # pyright: ignore[reportPrivateUsage]
    )

    completed = SessionStreamReader(
        session_commitment=session,
        profile=profile,
        cursor=advance.cursor,
        key_material=_KEY,
        partial_line=advance.partial_line,
    ).advance(path)

    assert completed.envelopes == ()
    assert completed.cursor.event_position == 0
    assert completed.cursor.byte_position == path.stat().st_size
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value in completed.gaps

    # The refusal is durable: appending an exact header and a record afterwards
    # never materializes events for a generation whose first line was rejected.
    with path.open("ab") as handle:
        handle.write(encode_lines(session_meta()))
    refused = SessionStreamReader(
        session_commitment=session,
        profile=profile,
        cursor=completed.cursor,
        key_material=_KEY,
        partial_line=completed.partial_line,
    ).advance(path)
    assert refused.envelopes == ()
    assert refused.cursor.event_position == 0
    assert refused.cursor.byte_position == completed.cursor.byte_position
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value in refused.gaps


def test_truncation_bumps_generation(tmp_path: Path) -> None:
    path = tmp_path / "session.jsonl"
    path.write_bytes(failed_shell_rollout())
    session = "hmac-sha256:" + ("c" * 64)
    reader = _reader(session)
    first = reader.advance(path)
    assert first.cursor.byte_position > 0
    path.write_bytes(encode_lines(session_meta(history_mode="paginated", ordinal=1)))
    second = reader.advance(path)
    assert second.truncated is True
    assert second.cursor.source_generation == first.cursor.source_generation + 1
    assert second.cursor.byte_position > 0


def test_restart_from_zero_is_stable(tmp_path: Path) -> None:
    path = tmp_path / "session.jsonl"
    path.write_bytes(encode_lines(session_meta()))
    session = "hmac-sha256:" + ("d" * 64)
    reader = _reader(session)
    one = reader.advance(path)
    two = reader.advance(path)
    assert two.envelopes == ()
    assert two.cursor.byte_position == one.cursor.byte_position


def test_exec_jsonl_grammar_is_unsupported_format(tmp_path: Path) -> None:
    path = tmp_path / "session.jsonl"
    path.write_bytes(
        b'{"type":"item.completed","item":{"id":"i1","type":"command_execution",'
        b'"command":"echo","aggregated_output":"ok","exit_code":0,"status":"completed"}}\n'
    )
    session = "hmac-sha256:" + ("e" * 64)
    advance = _reader(session).advance(path)
    assert advance.envelopes == ()
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value in advance.gaps
    assert ObservationGapCode.UNSUPPORTED_EVENT.value not in advance.gaps


def test_malformed_first_header_never_becomes_an_admitted_opaque_event(tmp_path: Path) -> None:
    path = tmp_path / "session.jsonl"
    path.write_bytes(b'{"payload":broken}\n' + encode_lines(session_meta()))
    session = "hmac-sha256:" + ("1" * 64)

    advance = _reader(session).advance(path)

    assert advance.envelopes == ()
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value in advance.gaps
    assert ObservationGapCode.UNSUPPORTED_EVENT.value not in advance.gaps


def test_reconcile_enqueues_recovered_envelopes_into_outbox(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions" / "2026" / "07" / "23"
    sessions.mkdir(parents=True)
    home.chmod(0o700)
    sessions.chmod(0o700)
    session_id = "019f8b27-b98e-7061-bbb5-d0b897594de6"
    target = sessions / f"rollout-2026-07-23T12-00-00-{session_id}.jsonl"
    target.write_bytes(failed_shell_rollout())
    os.chmod(target, 0o600)

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)
    assert store.pending_outbox_count(workspace) == 0

    locator = CodexSessionStreamLocator(home)
    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )
    assert result["resolved"] is True
    accepted = result["accepted"]
    assert isinstance(accepted, int) and accepted >= 1
    gaps = result["gaps"]
    assert isinstance(gaps, tuple)
    assert ObservationGapCode.UNSUPPORTED_EVENT.value not in gaps
    assert store.pending_outbox_count(workspace) == accepted


def test_reconcile_persists_unknown_event_before_advancing_cursor(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    session_id = "stream-unknown-event"
    target = sessions / f"rollout-{session_id}.jsonl"
    target.write_bytes(
        encode_lines(
            session_meta(),
            response_item({"type": "future_tool_result", "content": "must-not-persist"}),
        )
    )
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)

    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )

    assert result["resolved"] is True
    gaps = result["gaps"]
    assert isinstance(gaps, tuple)
    assert ObservationGapCode.UNSUPPORTED_EVENT.value in gaps
    assert result["byte_position"] == target.stat().st_size
    envelopes = store.list_envelopes(workspace)
    unsupported = [
        envelope
        for envelope in envelopes
        if ObservationGapCode.UNSUPPORTED_EVENT.value in envelope.gap_codes
    ]
    assert len(unsupported) == 1
    assert unsupported[0].event_kind == "unsupported_event"
    assert dict(unsupported[0].structural_payload) == {}
    assert b"must-not-persist" not in repr(unsupported[0]).encode()
    assert store.pending_outbox_count(workspace) == result["accepted"]
    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.UNSUPPORTED_EVENT.value in status.gaps


def test_reconcile_does_not_advance_past_a_rejected_envelope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    session_id = "stream-rejected-event"
    target = sessions / f"rollout-{session_id}.jsonl"
    target.write_bytes(failed_shell_rollout())
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)

    def reject(
        _store: LocalObservationStore,
        envelope: object,
    ) -> ObservationIngestResult:
        del envelope
        return ObservationIngestResult(
            ObservationIngestDisposition.REJECTED,
            ObservationGapCode.CURSOR_STALE.value,
            None,
        )

    monkeypatch.setattr(LocalObservationStore, "ingest", reject)
    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )

    assert result["accepted"] == 0
    assert result["byte_position"] == 0
    assert result["event_position"] == 0
    cursor = store.get_stream_cursor(workspace, session)
    assert cursor is not None
    assert cursor.byte_position == 0
    assert cursor.event_position == 0
    assert store.pending_outbox_count(workspace) == 0


@pytest.mark.parametrize("blocked_by", ["ingest", "outbox"])
def test_oversized_continuation_survives_final_envelope_backpressure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    blocked_by: str,
) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    session_id = f"stream-oversized-{blocked_by}-retry"
    target = sessions / f"rollout-{session_id}.jsonl"
    profile = default_stream_profile()
    target.write_bytes(
        encode_lines(session_meta())
        + b'{"type":"response_item","payload":"'
        + (b"x" * (profile.max_line_bytes + 10))
        + b'"}\n'
    )
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)
    locator = CodexSessionStreamLocator(home)

    for _ in range(2):
        reconcile_session_stream(
            store,
            workspace_commitment=workspace,
            session_commitment=session,
            codex_session_id=session_id,
            locator=locator,
        )
    before = store.get_stream_cursor(workspace, session)
    before_partial = store.get_stream_partial(workspace, session)
    assert before is not None and before.event_position == 1
    assert before_partial.startswith(
        stream_module._OVERSIZED_PARTIAL_PREFIX  # pyright: ignore[reportPrivateUsage]
    )

    with monkeypatch.context() as blocked:
        if blocked_by == "ingest":

            def reject(
                _store: LocalObservationStore,
                envelope: object,
            ) -> ObservationIngestResult:
                del envelope
                return ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.CURSOR_STALE.value,
                    None,
                )

            blocked.setattr(LocalObservationStore, "ingest", reject)
        else:

            def overflow(
                _store: LocalObservationStore,
                workspace_commitment: str,
                state: object,
                plan: object,
                incoming: object,
            ) -> AdmissionLossCause:
                del workspace_commitment, state, plan, incoming
                return AdmissionLossCause.QUEUE_COUNT

            blocked.setattr(LocalObservationStore, "_selected_admission_plan_refusal", overflow)
        failed = reconcile_session_stream(
            store,
            workspace_commitment=workspace,
            session_commitment=session,
            codex_session_id=session_id,
            locator=locator,
        )

    assert failed["byte_position"] == before.byte_position
    assert failed["event_position"] == before.event_position
    assert store.get_stream_partial(workspace, session) == before_partial

    retried = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )
    assert retried["event_position"] == 2
    assert retried["byte_position"] == target.stat().st_size
    assert store.get_stream_partial(workspace, session) == b""


def test_reconcile_resets_cursor_when_stream_mapping_changes(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions" / "2026" / "07" / "23"
    sessions.mkdir(parents=True)
    session_id = "019f8b27-b98e-7061-bbb5-d0b897594de6"
    target = sessions / f"rollout-2026-07-23T12-00-00-{session_id}.jsonl"
    target.write_bytes(failed_shell_rollout())
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)
    store.set_stream_cursor(
        workspace,
        session,
        ObservationCursor(
            source_generation=4,
            byte_position=target.stat().st_size,
            event_position=9,
            last_source_commitment=_EMPTY,
            mapping_version="codex-obs-stream/1.0.0",
        ),
    )

    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )
    cursor = store.get_stream_cursor(workspace, session)
    assert result["accepted"]
    assert cursor is not None
    assert cursor.mapping_version == STREAM_MAPPING_VERSION
    assert cursor.source_generation == 5
    assert cursor.byte_position > 0


def test_function_call_name_pairs_with_output_across_reconcile_passes(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    session_id = "stream-pair-across-passes"
    target = sessions / f"rollout-{session_id}.jsonl"
    target.write_bytes(
        encode_lines(
            session_meta(),
            function_call(name="shell", call_id="call-shell-cross-pass"),
        )
    )
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)
    locator = CodexSessionStreamLocator(home)
    first = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )
    assert first["accepted"] == 2
    target.write_bytes(
        target.read_bytes()
        + encode_lines(function_call_output(call_id="call-shell-cross-pass", exit_code=0))
    )
    second = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )
    assert second["accepted"] == 1
    outputs = [
        row.envelope
        for row in store.list_pending_outbox_rows(workspace)
        if row.envelope.structural_payload.get("action") == "function_call_output"
    ]
    assert len(outputs) == 1
    assert outputs[0].structural_payload.get("tool_name") == "shell"
    batch = materialize_observation_envelope(outputs[0], task_id="task_stream_pair")
    assert tuple(item.role for item in batch.drafts) == ("action", "result")


def test_originating_call_name_overrides_mismatched_output_name(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    session_id = "stream-pair-name-conflict"
    target = sessions / f"rollout-{session_id}.jsonl"
    target.write_bytes(
        encode_lines(
            session_meta(),
            function_call(name="shell", call_id="call-name-conflict"),
            response_item(
                {
                    "call_id": "call-name-conflict",
                    "exit_code": 0,
                    "name": "apply_patch",
                    "output": "ok",
                    "status": "completed",
                    "type": "function_call_output",
                }
            ),
        )
    )
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)

    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )

    assert result["accepted"] == 3
    output = next(
        row.envelope
        for row in store.list_pending_outbox_rows(workspace)
        if row.envelope.structural_payload.get("action") == "function_call_output"
    )
    assert output.structural_payload.get("tool_name") == "shell"
    assert ObservationGapCode.DEDUP_CONFLICT.value in output.gap_codes
    batch = materialize_observation_envelope(output, task_id="task_stream_pair_conflict")
    assert tuple(item.role for item in batch.drafts) == ("action", "result")


def test_output_without_same_generation_call_is_evidence_only(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    session_id = "stream-output-without-origin"
    target = sessions / f"rollout-{session_id}.jsonl"
    target.write_bytes(
        encode_lines(
            session_meta(),
            function_call_output(call_id="call-without-origin", exit_code=1),
        )
    )
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)

    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )

    assert result["accepted"] == 2
    output = next(
        row.envelope
        for row in store.list_pending_outbox_rows(workspace)
        if row.envelope.structural_payload.get("action") == "function_call_output"
    )
    assert ObservationGapCode.UNPAIRED_EVENT.value in output.gap_codes
    batch = materialize_observation_envelope(output, task_id="task_stream_unpaired")
    assert tuple(item.role for item in batch.drafts) == ("unpaired_evidence",)


def test_truncation_clears_persisted_call_pairing_across_store_restart(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    session_id = "stream-pair-truncated-generation"
    target = sessions / f"rollout-{session_id}.jsonl"
    target.write_bytes(
        encode_lines(
            session_meta(),
            function_call(name="shell", call_id="call-reused"),
            response_item(
                {
                    "content": [{"text": "x" * 2048, "type": "output_text"}],
                    "role": "assistant",
                    "type": "message",
                }
            ),
        )
    )
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)
    locator = CodexSessionStreamLocator(home)
    first = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )
    assert first["generation"] == 1

    target.write_bytes(
        encode_lines(session_meta(), function_call_output(call_id="call-reused", exit_code=0))
    )
    reopened = LocalObservationStore(_state=tmp_path)
    second = reconcile_session_stream(
        reopened,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )

    assert second["truncated"] is True
    assert second["generation"] == 2
    outputs = [
        row.envelope
        for row in reopened.list_pending_outbox_rows(workspace)
        if row.envelope.cursor.source_generation == 2
        and row.envelope.structural_payload.get("action") == "function_call_output"
    ]
    assert len(outputs) == 1
    assert "tool_name" not in outputs[0].structural_payload


def test_same_or_larger_rotation_clears_pairing_across_store_restart(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    session_id = "stream-pair-rotated-generation"
    target = sessions / f"rollout-{session_id}.jsonl"
    initial = encode_lines(
        session_meta(),
        function_call(name="shell", call_id="call-reused"),
    )
    target.write_bytes(initial)
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)
    locator = CodexSessionStreamLocator(home)
    reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )

    replacement = target.with_suffix(".replacement")
    rotated = encode_lines(
        session_meta(),
        function_call_output(call_id="call-reused", exit_code=0),
        response_item(
            {
                "content": [{"text": "y" * 2048, "type": "output_text"}],
                "role": "assistant",
                "type": "message",
            }
        ),
    )
    assert len(rotated) >= len(initial)
    replacement.write_bytes(rotated)
    os.replace(replacement, target)
    reopened = LocalObservationStore(_state=tmp_path)
    second = reconcile_session_stream(
        reopened,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )

    assert second["rotated"] is True
    assert second["generation"] == 2
    outputs = [
        row.envelope
        for row in reopened.list_pending_outbox_rows(workspace)
        if row.envelope.cursor.source_generation == 2
        and row.envelope.structural_payload.get("action") == "function_call_output"
    ]
    assert len(outputs) == 1
    assert "tool_name" not in outputs[0].structural_payload


@pytest.mark.parametrize("blocked_by", ["ingest", "outbox"])
def test_rotated_identity_retries_from_header_when_first_envelope_is_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    blocked_by: str,
) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    session_id = f"stream-rotation-{blocked_by}-retry"
    target = sessions / f"rollout-{session_id}.jsonl"
    initial = encode_lines(
        session_meta(),
        function_call(name="shell", call_id="call-old"),
    )
    target.write_bytes(initial)
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)
    locator = CodexSessionStreamLocator(home)
    reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )
    before = store.get_stream_cursor(workspace, session)
    assert before is not None and before.source_generation == 1

    replacement = target.with_suffix(".replacement")
    rotated = encode_lines(
        session_meta(),
        function_call_output(call_id="call-old", exit_code=0),
        response_item(
            {
                "content": [{"text": "z" * 2048, "type": "output_text"}],
                "role": "assistant",
                "type": "message",
            }
        ),
    )
    assert len(rotated) >= len(initial)
    replacement.write_bytes(rotated)
    os.replace(replacement, target)

    with monkeypatch.context() as blocked:
        if blocked_by == "ingest":

            def reject(
                _store: LocalObservationStore,
                envelope: object,
            ) -> ObservationIngestResult:
                del envelope
                return ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.CURSOR_STALE.value,
                    None,
                )

            blocked.setattr(LocalObservationStore, "ingest", reject)
        else:

            def overflow(
                _store: LocalObservationStore,
                workspace_commitment: str,
                state: object,
                plan: object,
                incoming: object,
            ) -> AdmissionLossCause:
                del workspace_commitment, state, plan, incoming
                return AdmissionLossCause.QUEUE_COUNT

            blocked.setattr(LocalObservationStore, "_selected_admission_plan_refusal", overflow)
        failed = reconcile_session_stream(
            LocalObservationStore(_state=tmp_path),
            workspace_commitment=workspace,
            session_commitment=session,
            codex_session_id=session_id,
            locator=locator,
        )

    assert failed["generation"] == 1
    assert failed["byte_position"] == before.byte_position
    retry_store = LocalObservationStore(_state=tmp_path)
    retried = reconcile_session_stream(
        retry_store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )

    assert retried["rotated"] is True
    assert retried["generation"] == 2
    assert retried["byte_position"] == len(rotated)
    outputs = [
        row.envelope
        for row in retry_store.list_pending_outbox_rows(workspace)
        if row.envelope.cursor.source_generation == 2
        and row.envelope.structural_payload.get("action") == "function_call_output"
    ]
    assert len(outputs) == 1
    assert "tool_name" not in outputs[0].structural_payload


def test_legacy_unfenced_call_pairing_is_discarded(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment("stream-legacy-call-tools")
    store.replace_stream_call_tools(
        workspace,
        session,
        source_generation=1,
        call_tools={"call-old": "shell"},
    )
    state_path = next((tmp_path / "observation" / "workspaces").glob("*.json"))
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    raw["schema"] = "yoetz.observation-local/8"
    raw["stream_call_tools"][session] = {"call-old": "shell"}
    state_path.write_text(json.dumps(raw), encoding="utf-8")

    reopened = LocalObservationStore(_state=tmp_path)

    assert (
        reopened.stream_call_tools_for_session(
            workspace,
            session,
            source_generation=1,
        )
        == {}
    )


def test_locator_matches_reverted_thread_filename(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions" / "2026" / "08" / "22"
    sessions.mkdir(parents=True)
    home.chmod(0o700)
    sessions.chmod(0o700)
    session_id = "019f8b27-b98e-7061-bbb5-d0b897594de6"
    rollout_id = "019f8b27-cccc-7061-bbb5-d0b897594de6"
    target = sessions / f"rollout-2026-08-22T12-00-00-{session_id}_{rollout_id}.jsonl"
    target.write_bytes(completed_shell_rollout())
    os.chmod(target, 0o600)
    locator = CodexSessionStreamLocator(home)
    assert locator.resolve(session_id=session_id) == target.resolve()


def test_compressed_rollout_is_explicit_unsupported_format(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions" / "2026" / "08" / "22"
    sessions.mkdir(parents=True)
    home.chmod(0o700)
    sessions.chmod(0o700)
    session_id = "019f8b27-b98e-7061-bbb5-d0b897594de6"
    target = sessions / f"rollout-2026-08-22T12-00-00-{session_id}.jsonl.zst"
    target.write_bytes(b"\x28\xb5\x2f\xfd" + b"not-a-real-frame")
    os.chmod(target, 0o600)
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)
    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )
    assert result["resolved"] is True
    assert result["accepted"] == 0
    assert result["gaps"] == (ObservationGapCode.UNSUPPORTED_FORMAT.value,)
    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value in status.gaps


def test_uncompressed_rollout_precedes_compressed_sibling(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions" / "2026" / "08" / "22"
    sessions.mkdir(parents=True)
    home.chmod(0o700)
    sessions.chmod(0o700)
    session_id = "019f8b27-b98e-7061-bbb5-d0b897594de6"
    plain = sessions / f"rollout-{session_id}.jsonl"
    compressed = sessions / f"rollout-{session_id}.jsonl.zst"
    plain.write_bytes(completed_shell_rollout())
    compressed.write_bytes(b"\x28\xb5\x2f\xfd" + b"not-a-real-frame")
    os.chmod(plain, 0o600)
    os.chmod(compressed, 0o600)
    locator = CodexSessionStreamLocator(home)
    assert locator.resolve(session_id=session_id) == plain.resolve()
    assert (
        locator.resolve(session_id=session_id, hook_provided_path=str(compressed))
        == plain.resolve()
    )

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)
    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )
    assert result["resolved"] is True
    accepted = result["accepted"]
    gaps = result["gaps"]
    assert type(accepted) is int and accepted > 0
    assert type(gaps) is tuple
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value not in gaps


def test_hook_stream_dedup_via_local_store(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment("stream-dedup")
    store.bind_session(workspace, session)
    path = tmp_path / "session.jsonl"
    path.write_bytes(failed_shell_rollout())
    reader = _reader(session)
    advance = reader.advance(path)
    assert len(advance.envelopes) >= 1
    first = store.ingest(advance.envelopes[0])
    second = store.ingest(advance.envelopes[0])
    assert first.disposition.value == "accepted"
    assert second.disposition.value == "duplicate"
    status = store.status(ObservationStatusQuery(workspace))
    assert status.source_coverage[ObservationSource.CODEX_SESSION_STREAM] is True


def test_locator_exact_session_match_and_rejects_ambiguous(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions" / "2026" / "07" / "23"
    sessions.mkdir(parents=True)
    home.chmod(0o700)
    sessions.chmod(0o700)
    session_id = "019f8b27-b98e-7061-bbb5-d0b897594de6"
    target = sessions / f"rollout-2026-07-23T12-00-00-{session_id}.jsonl"
    target.write_bytes(failed_shell_rollout())
    os.chmod(target, 0o600)
    locator = CodexSessionStreamLocator(home)
    resolved = locator.resolve(session_id=session_id)
    assert resolved == target.resolve()

    twin = sessions / f"other-{session_id}.jsonl"
    twin.write_bytes(encode_lines(session_meta()))
    os.chmod(twin, 0o600)
    assert locator.resolve(session_id=session_id) is None


@pytest.mark.parametrize(
    ("filename", "token", "expected"),
    [
        ("rollout-2026-07-23T12-00-00-root.jsonl", "root", True),
        ("rollout-2026-07-23T12-00-00-root_child.jsonl", "root", True),
        ("rollout-2026-07-23T12-00-00-root-child.jsonl", "root", False),
        ("rollout-2026-07-23T12-00-00-child-2.jsonl", "child", False),
        ("rollout-2026-07-23T12-00-00-child.jsonl", "child", True),
    ],
)
def test_rollout_filename_token_matching_rejects_prefix_and_suffix_collisions(
    filename: str, token: str, expected: bool
) -> None:
    assert stream_module.rollout_filename_matches_token(filename, token) is expected


@pytest.mark.parametrize(
    ("session_id", "name"),
    [
        ("root", "rollout-2026-07-23T12-00-00-root-child.jsonl"),
        ("child", "rollout-2026-07-23T12-00-00-child-2.jsonl"),
    ],
)
def test_locator_does_not_select_colliding_rollout_names(
    tmp_path: Path, session_id: str, name: str
) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions" / "2026" / "07" / "23"
    sessions.mkdir(parents=True)
    home.chmod(0o700)
    sessions.chmod(0o700)
    candidate = sessions / name
    candidate.write_bytes(failed_shell_rollout())
    os.chmod(candidate, 0o600)

    assert CodexSessionStreamLocator(home).resolve(session_id=session_id) is None


def test_locator_rejects_symlink_and_outside_home(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(failed_shell_rollout())
    link = sessions / "linked.jsonl"
    link.symlink_to(outside)
    locator = CodexSessionStreamLocator(home)
    assert locator.resolve(session_id="linked", hook_provided_path=str(link)) is None
    assert locator.resolve(session_id="outside", hook_provided_path=str(outside)) is None


def test_auto_reconcile_helper_persists_partial_and_cursor(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session_id = "auto-recon-1"
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)
    home = tmp_path / "codex-home"
    sessions = home / "sessions" / "2026" / "07" / "23"
    sessions.mkdir(parents=True)
    path = sessions / f"rollout-{session_id}.jsonl"
    prefix = encode_lines(session_meta(), terminated=True)
    body = encode_lines(
        function_call(name="shell", call_id="i1"),
        terminated=False,
    )
    path.write_bytes(prefix + body)
    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )
    assert result["resolved"] is True
    assert result["accepted"] == 1
    partial = store.get_stream_partial(workspace, session)
    assert partial.startswith(b'{"payload":')
    path.write_bytes(
        path.read_bytes() + b"\n" + encode_lines(function_call_output(call_id="i1", exit_code=0))
    )
    result2 = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )
    accepted = result2["accepted"]
    assert isinstance(accepted, int) and accepted >= 1
    assert store.get_stream_partial(workspace, session) == b""


def test_should_trigger_stream_reconcile_events() -> None:
    assert should_trigger_stream_reconcile("PostToolUse", last_reconcile_mono=None) is True
    assert should_trigger_stream_reconcile("Stop", last_reconcile_mono=None) is True
    assert (
        should_trigger_stream_reconcile(
            "SessionStart", last_reconcile_mono=None, session_source="resume"
        )
        is True
    )
    assert should_trigger_stream_reconcile("UserPromptSubmit", last_reconcile_mono=None) is False
    assert (
        should_trigger_stream_reconcile("UserPromptSubmit", last_reconcile_mono=0.0, now_mono=40.0)
        is True
    )


def test_function_call_output_maps_completed_tool_without_unknown_gap() -> None:
    record = CodexParsedRecord(
        1,
        0,
        80,
        "response_item",
        "function_call_output",
        JsonObject(
            {
                "payload": {
                    "call_id": "call-shell-1",
                    "exit_code": 1,
                    "name": "shell",
                    "status": "completed",
                    "type": "function_call_output",
                },
                "type": "response_item",
            }
        ),
    )
    envelope = envelope_from_stream_record(
        record,
        session_commitment="hmac-sha256:" + ("ab" * 32),
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=80,
            event_position=1,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
    )
    assert ObservationGapCode.UNSUPPORTED_EVENT.value not in envelope.gap_codes
    assert envelope.structural_payload.get("tool_name") == "shell"
    assert envelope.structural_payload.get("tool_call_id") == "call-shell-1"
    assert envelope.structural_payload.get("exit_status") == 1
    batch = materialize_observation_envelope(envelope, task_id="task_stream_map")
    assert tuple(item.role for item in batch.drafts) == ("action", "result")


def test_completed_masking_compound_command_preserves_outer_zero_with_nested_gap() -> None:
    record = CodexParsedRecord(
        1,
        0,
        160,
        "event_msg",
        "CommandExecution",
        JsonObject(
            {
                "payload": {
                    "item": {
                        "id": "command-compound",
                        "type": "CommandExecution",
                        "command": "pnpm vitest test/a.ts; tsc --noEmit",
                        "exit_code": 0,
                        "status": "completed",
                    },
                    "type": "item_completed",
                }
            }
        ),
    )
    envelope = envelope_from_stream_record(
        record,
        session_commitment="hmac-sha256:" + ("ae" * 32),
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=160,
            event_position=1,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
    )
    assert (
        envelope.structural_payload["runner_class"] == "test"
    )  # ADR-045: classed by its strongest verification
    assert envelope.structural_payload["exit_status"] == 0
    assert envelope.structural_payload["result_status"] == "completed"
    assert ObservationGapCode.COMPOUND_OUTCOME_UNAVAILABLE.value in envelope.gap_codes


def _rollout_command_envelope(command: str) -> ObservationEnvelope:
    record = CodexParsedRecord(
        1,
        0,
        160,
        "event_msg",
        "CommandExecution",
        JsonObject(
            {
                "payload": {
                    "item": {
                        "id": "command-write",
                        "type": "CommandExecution",
                        "command": command,
                        "exit_code": 0,
                        "status": "completed",
                    },
                    "type": "item_completed",
                }
            }
        ),
    )
    return envelope_from_stream_record(
        record,
        session_commitment="hmac-sha256:" + ("ae" * 32),
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=160,
            event_position=1,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
    )


@pytest.mark.parametrize(
    ("command", "scope"),
    [
        ("cat > solve.py <<'EOF'\nx\nEOF", "workspace"),
        # The agent's notes and Yoetz's own material keep their closed non-counting scope, so a
        # declared output of that kind can still override the exemption (ADR-045, Codex review).
        ("echo x > NOTES.md", "notes"),
        ("echo x > yoetz_receipt.md", "yoetz_owned"),
        ("echo done", None),
        # An absolute path says nothing without a workspace root; the hook claims those.
        ("echo x > /app/solve.py", None),
        # Two non-counting classes in one command keep counting (one token cannot carry both).
        (": > NOTES.md; : > yoetz_receipt.md", "workspace"),
    ],
)
def test_a_rollout_command_that_writes_carries_the_hooks_closed_write_scope(
    command: str, scope: str | None
) -> None:
    assert _rollout_command_envelope(command).structural_payload.get("write_scope") == scope


@pytest.mark.parametrize("vector", VECTORS, ids=[f"{n:03d}" for n, _ in enumerate(VECTORS)])
def test_a_rollout_command_earns_the_scope_the_shared_vectors_name(
    vector: ShellWriteVector,
) -> None:
    """tb4n3 shell-write review (#1028): the exact commands the domain and hook tests read, here
    as the Codex rollout stream sees them (no workspace root, so a relative write only), both bare
    and inside the ``/bin/bash -lc`` argv Codex really records."""

    from shlex import join

    wrapped = join(["/bin/bash", "-lc", vector.command])
    for command in (vector.command, wrapped):
        envelope = _rollout_command_envelope(command)
        assert envelope.structural_payload.get("write_scope") == vector.stream, command


def test_completed_and_compound_command_keeps_proven_zero_without_nested_gap() -> None:
    record = CodexParsedRecord(
        1,
        0,
        160,
        "event_msg",
        "CommandExecution",
        JsonObject(
            {
                "payload": {
                    "item": {
                        "id": "command-compound-and",
                        "type": "CommandExecution",
                        "command": "pnpm vitest test/a.ts && tsc --noEmit",
                        "exit_code": 0,
                        "status": "completed",
                    },
                    "type": "item_completed",
                }
            }
        ),
    )
    envelope = envelope_from_stream_record(
        record,
        session_commitment="hmac-sha256:" + ("af" * 32),
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=160,
            event_position=1,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
    )
    assert (
        envelope.structural_payload["runner_class"] == "test"
    )  # ADR-045: classed by its strongest verification
    assert envelope.structural_payload["exit_status"] == 0
    assert ObservationGapCode.COMPOUND_OUTCOME_UNAVAILABLE.value not in envelope.gap_codes


def test_function_call_output_preserves_negative_one_exit_status() -> None:
    record = CodexParsedRecord(
        1,
        0,
        80,
        "response_item",
        "function_call_output",
        JsonObject(
            {
                "payload": {
                    "call_id": "call-shell-negative",
                    "exit_code": -1,
                    "name": "shell",
                    "status": "completed",
                    "type": "function_call_output",
                },
                "type": "response_item",
            }
        ),
    )
    envelope = envelope_from_stream_record(
        record,
        session_commitment="hmac-sha256:" + ("ac" * 32),
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=80,
            event_position=1,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
    )
    assert ObservationGapCode.UNSUPPORTED_EVENT.value not in envelope.gap_codes
    assert envelope.structural_payload.get("exit_status") == -1
    batch = materialize_observation_envelope(envelope, task_id="task_stream_negative")
    result = batch.drafts[1].draft.payload
    assert isinstance(result, ResultRecordedPayload)
    assert result.outcome is ResultOutcome.FAILURE
    assert result.exit_status == -1


@pytest.mark.parametrize("exit_code", [-2, 256, True, "1"])
def test_function_call_output_rejects_out_of_profile_exit_status(exit_code: object) -> None:
    record = CodexParsedRecord(
        1,
        0,
        80,
        "response_item",
        "function_call_output",
        JsonObject(
            {
                "payload": {
                    "call_id": "call-shell-invalid-exit",
                    "exit_code": exit_code,
                    "name": "shell",
                    "status": "completed",
                    "type": "function_call_output",
                },
                "type": "response_item",
            }
        ),
    )
    envelope = envelope_from_stream_record(
        record,
        session_commitment="hmac-sha256:" + ("ad" * 32),
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=80,
            event_position=1,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
    )
    assert ObservationGapCode.UNSUPPORTED_EVENT.value in envelope.gap_codes
    assert "exit_status" not in envelope.structural_payload
    batch = materialize_observation_envelope(envelope, task_id="task_stream_invalid_exit")
    assert batch.skip_reason == "unsupported_or_gap"


def test_reconcile_retains_yoetz_self_observation_locally_and_advances_past_it(
    tmp_path: Path,
) -> None:
    """#564: the stream copy of a ``status`` call is the same self-observation the hook saw."""

    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    session_id = "stream-self-observation"
    target = sessions / f"rollout-{session_id}.jsonl"
    target.write_bytes(
        encode_lines(
            session_meta(),
            function_call(name="mcp__yoetz__status", call_id="y1", arguments="{}"),
            function_call_output(call_id="y1", output="private projection", exit_code=None),
            function_call(name="shell", call_id="s1", arguments='{"command":"pytest"}'),
            function_call_output(call_id="s1", output="ok", exit_code=0),
            function_call(name="mcp__yoetz__respond", call_id="y2", arguments="{}"),
            function_call_output(call_id="y2", output="recorded", exit_code=None),
            function_call(name="mcp__yoetz__status", call_id="y3", arguments="{}"),
            function_call_output(call_id="y3", output="error", exit_code=1),
        )
    )
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)

    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )

    assert result["resolved"] is True
    delivered = [
        (
            row.envelope.structural_payload.get("action"),
            row.envelope.structural_payload.get("tool_name"),
        )
        for row in store.list_pending_outbox_rows(workspace)
    ]
    assert delivered == [
        # session_meta is lifecycle, not a tool phase, and stays deliverable.
        (None, None),
        ("function_call", "shell"),
        ("function_call_output", "shell"),
        ("function_call_output", "mcp__yoetz__respond"),
        ("function_call_output", "mcp__yoetz__status"),
    ]
    # Every record was ingested locally and the cursor moved past all of them: a second
    # reconcile finds nothing new rather than re-reading the retained calls.
    accepted = result["accepted"]
    assert isinstance(accepted, int) and accepted >= 8
    assert store.selection_accounting(workspace)["intentionally_omitted_input_count"] == 4
    again = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )
    assert again["accepted"] == 0
    assert again["duplicates"] == 0
    assert store.pending_outbox_count(workspace) == 5


# --- exact per-version profiles (#568) -------------------------------------------------------

_PAGINATED_0150 = "imports/codex/rollout-paginated-0.150.1.case.json"
_UNSUPPORTED_0152 = "imports/codex/rollout-unsupported-0.152.1.case.json"
_CANARY_0150 = "CANARY_0150_"


def _fixture_bytes(path: str, variant: str) -> bytes:
    import base64

    from fixture_loader import build_fixture_loader

    case = cast(dict[str, object], build_fixture_loader().load_json(path))
    variants = cast(dict[str, object], cast(dict[str, object], case["input"])["variants"])
    source = cast(dict[str, object], cast(dict[str, object], variants[variant])["source"])
    return base64.b64decode(cast(str, source["bytes_base64"]).encode("ascii"), validate=True)


def _fixture_expected(path: str, variant: str) -> dict[str, object]:
    from fixture_loader import build_fixture_loader

    case = cast(dict[str, object], build_fixture_loader().load_json(path))
    expected = cast(dict[str, object], cast(dict[str, object], case["expected"])["variants"])
    return cast(dict[str, object], expected[variant])


def _header_selected_reader(session: str, *, generation: int = 1) -> SessionStreamReader:
    """A reader with no prior profile: the source header must select one."""

    return SessionStreamReader(
        session_commitment=session,
        profile=None,
        cursor=ObservationCursor(
            source_generation=generation,
            byte_position=0,
            event_position=0,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
        key_material=_KEY,
    )


def test_stream_profile_from_id_is_exact_lookup() -> None:
    assert stream_profile_from_id(None) is None
    assert stream_profile_from_id("codex-rollout-jsonl/0.152.1/v1") is None
    for version in ("0.148.0", "0.150.1"):
        profile = stream_profile_from_id(f"codex-rollout-jsonl/{version}/v1")
        assert profile is not None
        assert profile.cli_version == version


def test_0_150_1_stream_admits_from_header_and_envelopes_carry_no_content(
    tmp_path: Path,
) -> None:
    raw = _fixture_bytes(_PAGINATED_0150, "paginated")
    path = tmp_path / "session.jsonl"
    path.write_bytes(raw)
    session = "hmac-sha256:" + ("5" * 64)
    reader = _header_selected_reader(session)

    advance = reader.advance(path)

    assert reader.profile is not None
    assert reader.profile.profile_id == "codex-rollout-jsonl/0.150.1/v1"
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value not in advance.gaps
    assert ObservationGapCode.UNSUPPORTED_EVENT.value not in advance.gaps
    assert advance.cursor.byte_position == len(raw)
    assert advance.cursor.event_position == raw.count(b"\n")
    assert len(advance.envelopes) == raw.count(b"\n")
    kinds = {envelope.structural_payload["stream_kind"] for envelope in advance.envelopes}
    assert kinds == set(reader.profile.wrapper_types)
    actions = {
        envelope.structural_payload.get("action")
        for envelope in advance.envelopes
        if "action" in envelope.structural_payload
    }
    assert {"function_call", "custom_tool_call", "McpToolCall", "CommandExecution"} <= actions
    # Since 0.150.1 every response-item row names itself (``fc_``/``ctc_``) beside the ``call_id``
    # its output shares; each call and its output carry that shared id (#1038).
    call_ids = {
        str(envelope.structural_payload.get("action")): envelope.structural_payload.get(
            "tool_call_id"
        )
        for envelope in advance.envelopes
        if envelope.structural_payload.get("action")
        in {"function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output"}
    }
    assert call_ids["function_call"] == call_ids["function_call_output"] == "call_yoetz_1"
    assert call_ids["custom_tool_call"] == call_ids["custom_tool_call_output"] == "call_shell_1"
    dumped = json.dumps(
        [
            {
                "event_kind": envelope.event_kind,
                "structural_payload": dict(envelope.structural_payload),
                "content_object_refs": list(envelope.content_object_refs),
                "gap_codes": list(envelope.gap_codes),
            }
            for envelope in advance.envelopes
        ],
        default=str,
    )
    # Hidden reasoning, base instructions, developer/user/assistant text, tool output,
    # compaction summaries, world state, and the secret canary all stay out of every envelope.
    assert _CANARY_0150 not in dumped
    assert "sk-proj-" not in dumped
    assert "[REDACTED]" not in dumped
    assert all(envelope.content_object_refs == () for envelope in advance.envelopes)
    allowed = {
        "stream_kind",
        "action",
        "tool_name",
        "result_status",
        "runner_class",
        "exit_status",
        "tool_call_id",
        "subagent_id",
        # A completed command's installation-keyed identity (#909, #910), never its text.
        "command_commitment",
    }
    for envelope in advance.envelopes:
        assert set(envelope.structural_payload) <= allowed, envelope.structural_payload

    subagent = next(
        envelope
        for envelope in advance.envelopes
        if envelope.structural_payload.get("subagent_id") is not None
    )
    assert subagent.event_kind == "SubagentStart"
    assert subagent.structural_payload["subagent_id"] == ("019f8b27-b98e-7061-bbb5-d0b897594de7")
    # The rollout item's ``id`` is not the parent's tool-call id.  The stream
    # copy therefore remains child-only and can reconcile with a hook copy
    # whose parent tool alias is absent or arrives separately.
    assert "parent_tool_call_id" not in subagent.structural_payload
    assert "tool_call_id" not in subagent.structural_payload
    assert (
        materialize_observation_envelope(
            subagent, task_id="tsk_00000000-0000-4000-8000-000000000001"
        ).skip_reason
        is None
    )


def test_subagent_stream_accepts_explicit_parent_alias_but_ignores_item_id() -> None:
    record = CodexParsedRecord(
        1,
        0,
        160,
        "response_item",
        "SubAgentActivity",
        JsonObject(
            {
                "payload": {
                    "agent_thread_id": "child-stream-1",
                    "id": "item-child-1",
                    "kind": "started",
                    "tool_use_id": "parent-tool-1",
                    "type": "SubAgentActivity",
                },
                "type": "response_item",
            }
        ),
    )

    structural, gaps = stream_module.structural_from_stream_record(record)

    assert gaps == ()
    assert structural["subagent_id"] == "child-stream-1"
    assert structural["parent_tool_call_id"] == "parent-tool-1"
    assert "tool_call_id" not in structural


@pytest.mark.parametrize("kind", ["started", "completed"])
@pytest.mark.parametrize(
    "parent_aliases",
    [
        {"parent_tool_call_id": "spawn-call", "tool_use_id": "other-call"},
        {"parent_tool_call_id": "spawn-call", "tool_call_id": "other-call"},
        {"parent_tool_call_id": {"invalid": "token"}},
        {"tool_use_id": {"invalid": "token"}},
        {"tool_call_id": None},
    ],
)
def test_subagent_stream_invalid_parent_alias_cannot_weaken_identity(
    kind: str, parent_aliases: dict[str, Any]
) -> None:
    from yoetz.domain.host_lineage import host_lineage_from_envelope

    record = CodexParsedRecord(
        1,
        0,
        160,
        "response_item",
        "SubAgentActivity",
        JsonObject(
            {
                "payload": {
                    "agent_thread_id": "child-stream-1",
                    "kind": kind,
                    "type": "SubAgentActivity",
                    **parent_aliases,
                },
                "type": "response_item",
            }
        ),
    )
    envelope = envelope_from_stream_record(
        record,
        session_commitment=_EMPTY,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=160,
            event_position=1,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
    )

    assert envelope.event_kind in {"SubagentStart", "SubagentStop"}
    assert envelope.gap_codes == (ObservationGapCode.MISSING_SUBAGENT_IDENTITY.value,)
    assert "subagent_id" not in envelope.structural_payload
    assert "parent_tool_call_id" not in envelope.structural_payload
    assert host_lineage_from_envelope(envelope) is None
    batch = materialize_observation_envelope(
        envelope, task_id="tsk_00000000-0000-4000-8000-000000000001"
    )
    assert batch.skip_reason == "missing_subagent_identity"
    assert batch.drafts == ()


def test_unsupported_release_is_refused_durably_without_cursor_loss(tmp_path: Path) -> None:
    raw = _fixture_bytes(_UNSUPPORTED_0152, "future")
    path = tmp_path / "session.jsonl"
    path.write_bytes(raw)
    session = "hmac-sha256:" + ("6" * 64)
    reader = _header_selected_reader(session)

    advance = reader.advance(path)

    assert reader.profile is None
    assert advance.envelopes == ()
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value in advance.gaps
    assert ObservationGapCode.UNSUPPORTED_EVENT.value not in advance.gaps
    # The bytes are consumed (no re-read storm) and no event is counted as admitted.
    assert advance.cursor.byte_position == len(raw)
    assert advance.cursor.event_position == 0

    path.write_bytes(raw + encode_lines(function_call(name="shell", call_id="later", ordinal=4)))
    appended = reader.advance(path)
    assert appended.envelopes == ()
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value in appended.gaps
    assert appended.cursor.event_position == 0
    # The refusal point is held for the whole generation: the appended tail is never read, so
    # nothing of an unproven grammar is interpreted, and the cursor is neither lost nor rewound.
    assert appended.cursor.byte_position == len(raw)
    assert appended.cursor.source_generation == advance.cursor.source_generation


def test_prior_profile_refuses_a_rotated_source_of_another_release(tmp_path: Path) -> None:
    path = tmp_path / "session.jsonl"
    path.write_bytes(
        encode_lines(
            session_meta(),
            function_call(name="shell", call_id="a", arguments='{"command":"echo one"}'),
            function_call_output(call_id="a"),
            function_call(name="shell", call_id="b", arguments='{"command":"echo two"}'),
            function_call_output(call_id="b"),
        )
    )
    session = "hmac-sha256:" + ("7" * 64)
    reader = _header_selected_reader(session)
    first = reader.advance(path)
    assert reader.profile is not None and reader.profile.cli_version == "0.148.0"
    assert len(first.envelopes) == 5

    # Truncation starts a new generation whose header re-selects the profile from scratch.
    path.write_bytes(
        encode_lines(
            session_meta(cli_version="0.150.1", history_mode="paginated", ordinal=1),
            function_call(name="shell", call_id="b", ordinal=2),
        )
    )
    second = reader.advance(path)
    assert second.truncated is True
    assert second.cursor.source_generation == first.cursor.source_generation + 1
    assert reader.profile is not None and reader.profile.cli_version == "0.150.1"
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value not in second.gaps
    assert len(second.envelopes) == 2


def test_unknown_inner_item_under_0_150_1_is_opaque_unsupported_event(tmp_path: Path) -> None:
    path = tmp_path / "session.jsonl"
    path.write_bytes(
        encode_lines(
            session_meta(cli_version="0.150.1", history_mode="paginated", ordinal=1),
            item_completed({"id": "item_x", "type": "FutureItem", "text": "secret-ish"}, ordinal=2),
            {
                "ordinal": 3,
                "payload": {"tokens": 1},
                "timestamp": "t",
                "type": "token_usage_record",
            },
            function_call(name="shell", call_id="after", ordinal=4),
        )
    )
    session = "hmac-sha256:" + ("8" * 64)
    reader = _header_selected_reader(session)

    advance = reader.advance(path)

    assert ObservationGapCode.UNSUPPORTED_FORMAT.value not in advance.gaps
    assert ObservationGapCode.UNSUPPORTED_EVENT.value in advance.gaps
    assert advance.cursor.event_position == 4
    opaque = [
        envelope
        for envelope in advance.envelopes
        if ObservationGapCode.UNSUPPORTED_EVENT.value in envelope.gap_codes
    ]
    assert len(opaque) == 2
    assert all("secret-ish" not in json.dumps(dict(e.structural_payload)) for e in opaque)
    assert all("FutureItem" not in json.dumps(dict(e.structural_payload)) for e in opaque)
    assert advance.envelopes[-1].structural_payload["tool_name"] == "shell"


def test_admitted_generation_without_recorded_profile_replays_from_header(
    tmp_path: Path,
) -> None:
    path = tmp_path / "session.jsonl"
    body = encode_lines(
        session_meta(cli_version="0.150.1", history_mode="paginated", ordinal=1),
        function_call(name="shell", call_id="a", ordinal=2),
    )
    path.write_bytes(body)
    session = "hmac-sha256:" + ("9" * 64)
    reader = SessionStreamReader(
        session_commitment=session,
        profile=None,
        cursor=ObservationCursor(
            source_generation=3,
            byte_position=len(body),
            event_position=2,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
        key_material=_KEY,
    )

    advance = reader.advance(path)

    assert advance.restarted is True
    assert ObservationGapCode.CURSOR_STALE.value in advance.gaps
    assert advance.cursor.source_generation == 4
    assert advance.cursor.event_position == 2
    assert reader.profile is not None and reader.profile.cli_version == "0.150.1"
    assert len(advance.envelopes) == 2


def test_reconcile_persists_admitted_profile_and_resets_1_2_0_cursors(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions" / "2026" / "07" / "23"
    sessions.mkdir(parents=True)
    session_id = "019f8b27-b98e-7061-bbb5-d0b897594de6"
    target = sessions / f"rollout-2026-07-23T12-00-00-{session_id}.jsonl"
    target.write_bytes(_fixture_bytes(_PAGINATED_0150, "paginated"))
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)
    # A pre-#568 cursor never recorded which profile admitted its generation; it must replay
    # under the new mapping rather than inherit the 0.148.0 default.
    store.set_stream_cursor(
        workspace,
        session,
        ObservationCursor(
            source_generation=2,
            byte_position=target.stat().st_size,
            event_position=30,
            last_source_commitment=_EMPTY,
            mapping_version="codex-obs-stream/1.2.0",
        ),
    )

    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )

    assert result["resolved"] is True
    assert result["profile_id"] == "codex-rollout-jsonl/0.150.1/v1"
    assert store.stream_profile_for_session(workspace, session) == (
        "codex-rollout-jsonl/0.150.1/v1"
    )
    cursor = store.get_stream_cursor(workspace, session)
    assert cursor is not None
    assert cursor.mapping_version == STREAM_MAPPING_VERSION
    assert cursor.source_generation == 3
    accepted = result["accepted"]
    assert isinstance(accepted, int) and accepted >= 1
    gaps = result["gaps"]
    assert isinstance(gaps, tuple)
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value not in gaps
    assert ObservationGapCode.UNSUPPORTED_EVENT.value not in gaps

    # A second pass reuses the persisted profile and makes no progress without new bytes.
    again = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )
    assert again["accepted"] == 0
    assert again["profile_id"] == "codex-rollout-jsonl/0.150.1/v1"


def test_reconcile_of_unsupported_release_records_no_profile(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions" / "2026" / "07" / "23"
    sessions.mkdir(parents=True)
    session_id = "019f8b27-b98e-7061-bbb5-d0b897594de6"
    target = sessions / f"rollout-2026-07-23T12-00-00-{session_id}.jsonl"
    target.write_bytes(_fixture_bytes(_UNSUPPORTED_0152, "future"))
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)

    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )

    assert result["resolved"] is True
    assert result["accepted"] == 0
    assert result["profile_id"] is None
    gaps = result["gaps"]
    assert isinstance(gaps, tuple)
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value in gaps
    assert store.stream_profile_for_session(workspace, session) is None
    cursor = store.get_stream_cursor(workspace, session)
    assert cursor is not None
    assert cursor.byte_position == target.stat().st_size
    assert cursor.event_position == 0


# --- structural admission (#656) --------------------------------------------------------------

_COMPATIBLE_0153 = "imports/codex/rollout-compatible-0.153.4.case.json"
_COMPATIBLE_PROFILE_ID = "codex-rollout-jsonl/compatible/v1"


def test_unproven_release_is_admitted_under_the_compatible_profile(tmp_path: Path) -> None:
    """The header version is provenance only: a 0.153.4 label parses the 0.150.1 structure under
    the structural profile, maps every known line, and keeps every canary out of envelopes."""

    raw = _fixture_bytes(_COMPATIBLE_0153, "relabeled")
    exact_raw = _fixture_bytes(_PAGINATED_0150, "paginated")
    path = tmp_path / "session.jsonl"
    path.write_bytes(raw)
    session = "hmac-sha256:" + ("a" * 64)
    reader = _header_selected_reader(session)

    advance = reader.advance(path)

    assert reader.profile is not None
    assert reader.profile.profile_id == _COMPATIBLE_PROFILE_ID
    assert stream_profile_from_id(_COMPATIBLE_PROFILE_ID) is reader.profile
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value not in advance.gaps
    assert ObservationGapCode.UNSUPPORTED_EVENT.value not in advance.gaps
    assert advance.reason_codes == ()
    assert advance.cursor.byte_position == len(raw)
    assert advance.cursor.event_position == exact_raw.count(b"\n")
    assert len(advance.envelopes) == exact_raw.count(b"\n")
    dumped = json.dumps(
        [dict(envelope.structural_payload) for envelope in advance.envelopes], default=str
    )
    assert _CANARY_0150 not in dumped
    assert "0.153.4" not in dumped
    # Structural admission is reported apart from certification.
    assert (
        stream_module.stream_admission(reader.profile, advance.gaps, advance.reason_codes)
        == "partially_understood"
    )


def test_additive_fields_never_reach_observation_envelopes(tmp_path: Path) -> None:
    raw = _fixture_bytes(_COMPATIBLE_0153, "additive")
    assert b"CANARY_0153_ADDITIVE" in raw
    path = tmp_path / "session.jsonl"
    path.write_bytes(raw)
    reader = _header_selected_reader("hmac-sha256:" + ("b" * 64))

    advance = reader.advance(path)

    assert ObservationGapCode.UNSUPPORTED_EVENT.value not in advance.gaps
    assert len(advance.envelopes) == raw.count(b"\n")
    dumped = json.dumps(
        [
            {
                "structural_payload": dict(envelope.structural_payload),
                "content_object_refs": list(envelope.content_object_refs),
                "gap_codes": list(envelope.gap_codes),
            }
            for envelope in advance.envelopes
        ],
        default=str,
    )
    assert "CANARY_0153_ADDITIVE" not in dumped
    assert "x_future" not in dumped


def test_unknown_and_incompatible_lines_stay_bounded_under_compatible_profile(
    tmp_path: Path,
) -> None:
    session = "hmac-sha256:" + ("c" * 64)
    path = tmp_path / "session.jsonl"

    path.write_bytes(_fixture_bytes(_COMPATIBLE_0153, "unknown_event"))
    unknown = _header_selected_reader(session).advance(path)
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value not in unknown.gaps
    assert ObservationGapCode.UNSUPPORTED_EVENT.value in unknown.gaps
    assert unknown.reason_codes == ("unknown_item_type", "unknown_wrapper_type")
    assert unknown.cursor.event_position == 5
    opaque = [
        e for e in unknown.envelopes if ObservationGapCode.UNSUPPORTED_EVENT.value in e.gap_codes
    ]
    assert len(opaque) == 2
    dumped = json.dumps([dict(e.structural_payload) for e in unknown.envelopes], default=str)
    assert "CANARY_0153" not in dumped and "FutureItem" not in dumped
    # The independent known call/output after the unknown lines still map and pair.
    assert unknown.envelopes[-2].structural_payload["tool_name"] == "shell"
    assert unknown.envelopes[-1].structural_payload.get("result_status") is not None

    path.write_bytes(_fixture_bytes(_COMPATIBLE_0153, "incompatible_known"))
    incompatible = _header_selected_reader(session).advance(path)
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value not in incompatible.gaps
    assert ObservationGapCode.UNSUPPORTED_EVENT.value in incompatible.gaps
    assert incompatible.reason_codes == ("wrapper_shape_unsupported",)
    assert incompatible.cursor.event_position == 4
    bounded = [
        e
        for e in incompatible.envelopes
        if ObservationGapCode.UNSUPPORTED_EVENT.value in e.gap_codes
    ]
    assert len(bounded) == 2
    # A malformed known wrapper mints no action, result, or pairing identity.
    assert all(
        "action" not in e.structural_payload and "tool_call_id" not in e.structural_payload
        for e in bounded
    )
    assert "CANARY_0153_STRING_PAYLOAD" not in json.dumps(
        [dict(e.structural_payload) for e in incompatible.envelopes], default=str
    )
    assert incompatible.envelopes[-1].structural_payload["tool_name"] == "shell"

    path.write_bytes(_fixture_bytes(_COMPATIBLE_0153, "truncated"))
    truncated = _header_selected_reader(session).advance(path)
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value not in truncated.gaps
    # The unterminated tail is held for the next read, not lost (#1041).
    assert ObservationGapCode.TRUNCATED_PAYLOAD.value not in truncated.gaps
    assert truncated.cursor.event_position == 2
    assert truncated.partial_line.startswith(b"{")


_MULTI_AGENT_V2_0153 = "imports/codex/rollout-multi-agent-v2-0.153.4.case.json"


def test_multi_agent_v2_parent_stream_names_one_delegation_without_gaps(tmp_path: Path) -> None:
    """Issue #754: a v2 parent turn maps every line and starts exactly one delegation.

    The spawn arrives as an ``event_msg.item_completed`` ``SubAgentActivity`` item, which is
    where 0.153.4 v2 puts it; every later exchange is ``interacted``, a known kind that names no
    lifecycle transition and so opens no second annotation.
    """

    session = "hmac-sha256:" + ("d" * 64)
    path = tmp_path / "session.jsonl"
    path.write_bytes(_fixture_bytes(_MULTI_AGENT_V2_0153, "parent"))

    advance = _header_selected_reader(session).advance(path)

    assert advance.gaps == ()
    assert advance.reason_codes == ()
    assert advance.cursor.event_position == 8
    assert all(envelope.gap_codes == () for envelope in advance.envelopes)
    expected = _fixture_expected(_MULTI_AGENT_V2_0153, "parent")
    starts = [e for e in advance.envelopes if e.event_kind == "SubagentStart"]
    assert len(starts) == expected["subagent_start_count"]
    assert starts[0].structural_payload["subagent_id"] == expected["subagent_id"]
    # The spawn item's own ``id`` is not published as the parent call: only an explicit alias is.
    assert expected["parent_tool_call_id"] is None
    assert "parent_tool_call_id" not in starts[0].structural_payload
    assert "tool_call_id" not in starts[0].structural_payload
    interacted = [
        e
        for e in advance.envelopes
        if e.structural_payload.get("action") == "SubAgentActivity" and e.event_kind == "event_msg"
    ]
    assert len(interacted) == 1
    assert host_lineage_from_envelope(interacted[0]) is None
    # The families 0.153.4 added are ordinary understood lines now, not coverage gaps.
    assert {cast(str, e.structural_payload["stream_kind"]) for e in advance.envelopes} == {
        "session_meta",
        "turn_context",
        "event_msg",
        "response_item",
        "inter_agent_communication_metadata",
        "token_usage_record",
    }


def test_multi_agent_v2_child_header_is_that_childs_own_start(tmp_path: Path) -> None:
    """The delegated child's own header is the only place v2 names the delegation."""

    session = "hmac-sha256:" + ("e" * 64)
    path = tmp_path / "session.jsonl"
    path.write_bytes(_fixture_bytes(_MULTI_AGENT_V2_0153, "child"))

    advance = _header_selected_reader(session).advance(path)

    assert advance.gaps == ()
    expected = _fixture_expected(_MULTI_AGENT_V2_0153, "child")
    header = advance.envelopes[0]
    assert header.event_kind == "SubagentStart"
    assert header.structural_payload["stream_kind"] == "session_meta"
    assert header.structural_payload["subagent_id"] == expected["subagent_id"]
    # The header's ``id`` is a thread, never a parent tool call.
    assert "tool_call_id" not in header.structural_payload
    assert "parent_tool_call_id" not in header.structural_payload
    observation = host_lineage_from_envelope(header)
    assert observation is not None
    assert observation.phase == "start"
    assert observation.correlation.subagent_id == expected["subagent_id"]
    assert (
        materialize_observation_envelope(
            header, task_id="tsk_00000000-0000-4000-8000-000000000001"
        ).skip_reason
        is None
    )
    # A child reports its exchanges with the root in the same family, with the root thread in
    # ``agent_thread_id``. Without a start kind it never publishes the parent as a child.
    reversed_row = advance.envelopes[-1]
    assert reversed_row.event_kind == "event_msg"
    assert host_lineage_from_envelope(reversed_row) is None


def test_multi_agent_v2_child_header_without_identity_keeps_the_bounded_gap(
    tmp_path: Path,
) -> None:
    """A declared child with no distinct spawning thread is the genuine identity gap."""

    session = "hmac-sha256:" + ("f" * 64)
    path = tmp_path / "session.jsonl"
    path.write_bytes(_fixture_bytes(_MULTI_AGENT_V2_0153, "child_without_identity"))

    advance = _header_selected_reader(session).advance(path)

    expected = _fixture_expected(_MULTI_AGENT_V2_0153, "child_without_identity")
    header = advance.envelopes[0]
    assert header.event_kind == "SubagentStart"
    assert expected["subagent_id"] is None
    assert list(header.gap_codes) == expected["gap_codes"]
    assert header.gap_codes == (ObservationGapCode.MISSING_SUBAGENT_IDENTITY.value,)
    assert "subagent_id" not in header.structural_payload
    assert host_lineage_from_envelope(header) is None
    assert (
        materialize_observation_envelope(
            header, task_id="tsk_00000000-0000-4000-8000-000000000001"
        ).skip_reason
        == "missing_subagent_identity"
    )


@pytest.mark.parametrize(
    "payload",
    [
        # A parent thread declares no child at all.
        {"id": "child-1", "parent_thread_id": "parent-1", "thread_source": "user"},
        # Contradictory spellings of the spawning thread.
        {
            "id": "child-1",
            "parent_thread_id": "parent-1",
            "source": {"subagent": {"thread_spawn": {"parent_thread_id": "parent-2"}}},
            "thread_source": "subagent",
        },
        # A path-shaped or otherwise unusable child token.
        {"id": "/root/child", "parent_thread_id": "parent-1", "thread_source": "subagent"},
        # v2 sets ``session_id`` to the parent thread; a header naming itself is refused.
        {"id": "parent-1", "parent_thread_id": "parent-1", "thread_source": "subagent"},
    ],
)
def test_child_session_identity_never_invents_a_delegation(payload: dict[str, Any]) -> None:
    record = CodexParsedRecord(
        1,
        0,
        200,
        "session_meta",
        None,
        JsonObject({"payload": payload, "type": "session_meta"}),
    )

    structural, gaps = stream_module.structural_from_stream_record(record)

    assert "subagent_id" not in structural
    declared_child = payload["thread_source"] == "subagent"
    assert (ObservationGapCode.MISSING_SUBAGENT_IDENTITY.value in gaps) is declared_child


_V2_ROOT = "019f8b27-b98e-7061-bbb5-d0b897594de6"
_V2_CHILD = "019f8b27-b98e-7061-bbb5-d0b897594de7"


@pytest.mark.parametrize(
    ("variant", "status"),
    [("child", "child"), ("child_without_identity", "identity_invalid"), ("parent", "not_child")],
)
def test_child_rollout_header_reads_only_the_first_v2_line(
    tmp_path: Path, variant: str, status: str
) -> None:
    """Issue #841: one bounded first-line read classifies a rollout as a delegated child."""

    path = tmp_path / "rollout.jsonl"
    # Trailing garbage after the header proves nothing past the first newline is read.
    path.write_bytes(_fixture_bytes(_MULTI_AGENT_V2_0153, variant) + b"\x00not json\n")

    result = stream_module.read_codex_child_rollout_header(path)

    assert result.status == status
    if status == "child":
        assert result.header is not None
        assert result.header.child_thread_id == _V2_CHILD
        # v2 names the root session and the spawning thread; both are the parent here.
        assert result.header.spawning_sessions == (_V2_ROOT,)
        assert _V2_CHILD not in repr(result) and _V2_CHILD not in repr(result.header)
    else:
        assert result.header is None


def test_child_rollout_header_orders_root_session_before_spawning_thread(tmp_path: Path) -> None:
    """A nested child's lane belongs to the root session its callbacks carry."""

    nested = "019f8b27-b98e-7061-bbb5-d0b897594de8"
    header = session_meta(
        cli_version="0.153.4",
        history_mode="paginated",
        session_id=nested,
        extra={
            "session_id": _V2_ROOT,
            "thread_source": "subagent",
            "parent_thread_id": _V2_CHILD,
            "source": {"subagent": {"thread_spawn": {"parent_thread_id": _V2_CHILD}}},
        },
    )
    path = tmp_path / "rollout.jsonl"
    path.write_bytes(encode_lines(header))

    result = stream_module.read_codex_child_rollout_header(path)

    assert result.header is not None
    assert result.header.child_thread_id == nested
    assert result.header.spawning_sessions == (_V2_ROOT, _V2_CHILD)


@pytest.mark.parametrize("shape", ["unterminated", "compressed", "symlink", "missing", "oversized"])
def test_child_rollout_header_refuses_what_it_cannot_prove(tmp_path: Path, shape: str) -> None:
    child = _fixture_bytes(_MULTI_AGENT_V2_0153, "child")
    first_line = child.split(b"\n", 1)[0]
    path = tmp_path / "rollout.jsonl"
    if shape == "unterminated":
        path.write_bytes(first_line)
    elif shape == "compressed":
        path = tmp_path / "rollout.jsonl.zst"
        path.write_bytes(child)
    elif shape == "symlink":
        target = tmp_path / "target.jsonl"
        target.write_bytes(child)
        path.symlink_to(target)
    elif shape == "oversized":
        path.write_bytes(b"{" + b" " * (ROLLOUT_MAX_LINE_BYTES + 8) + b"}\n")

    assert stream_module.read_codex_child_rollout_header(path).status == "unreadable"


def _child_home(tmp_path: Path) -> tuple[CodexSessionStreamLocator, Path]:
    home = tmp_path / "codex-home"
    day = home / "sessions" / "2026" / "08" / "22"
    day.mkdir(parents=True)
    return CodexSessionStreamLocator(home), day


def test_child_rollout_locator_binds_the_header_to_its_thread_filename(tmp_path: Path) -> None:
    locator, day = _child_home(tmp_path)
    child = day / f"rollout-2026-08-22T12-00-01-{_V2_CHILD}.jsonl"
    child.write_bytes(_fixture_bytes(_MULTI_AGENT_V2_0153, "child"))

    by_path, by_path_result = locator.resolve_child_rollout(str(child))
    by_thread, _ = locator.resolve_child_rollout(None, child_thread_id=_V2_CHILD)
    checked, _ = locator.resolve_child_rollout(str(child), child_thread_id=_V2_CHILD)

    assert by_path == by_thread == checked == child.resolve()
    assert by_path_result.status == "child"
    # A different child than the caller named proves nothing about the requested rollout.
    assert locator.resolve_child_rollout(str(child), child_thread_id=_V2_ROOT)[0] is None
    assert locator.resolve_child_rollout(None)[0] is None


def test_child_rollout_locator_refuses_a_header_under_another_threads_name(
    tmp_path: Path,
) -> None:
    locator, day = _child_home(tmp_path)
    copied = day / f"rollout-2026-08-22T12-00-01-{_V2_ROOT}.jsonl"
    copied.write_bytes(_fixture_bytes(_MULTI_AGENT_V2_0153, "child"))
    outside = tmp_path / f"rollout-2026-08-22T12-00-01-{_V2_CHILD}.jsonl"
    outside.write_bytes(_fixture_bytes(_MULTI_AGENT_V2_0153, "child"))

    for candidate in (copied, outside):
        path, result = locator.resolve_child_rollout(str(candidate))
        assert path is None
        assert result.status == "unreadable"
    assert locator.resolve_child_rollout(None, child_thread_id="../escape")[0] is None


def test_child_rollout_locator_reports_a_declared_child_without_identity(tmp_path: Path) -> None:
    locator, day = _child_home(tmp_path)
    invalid = day / f"rollout-2026-08-22T12-00-01-{_V2_ROOT}.jsonl"
    invalid.write_bytes(_fixture_bytes(_MULTI_AGENT_V2_0153, "child_without_identity"))

    path, result = locator.resolve_child_rollout(str(invalid))

    assert path is None
    assert result.status == "identity_invalid"


def test_stream_admission_classification_is_closed_and_honest() -> None:
    exact = stream_profile_from_id("codex-rollout-jsonl/0.150.1/v1")
    compatible = stream_profile_from_id(_COMPATIBLE_PROFILE_ID)
    assert exact is not None and compatible is not None
    admission = stream_module.stream_admission
    assert admission(exact, (), ()) == "structurally_supported"
    assert admission(
        exact, (ObservationGapCode.UNSUPPORTED_EVENT.value,), ("unknown_item_type",)
    ) == ("partially_understood")
    assert admission(compatible, (), ()) == "partially_understood"
    assert admission(None, (ObservationGapCode.UNSUPPORTED_FORMAT.value,), ()) == "incompatible"
    assert admission(exact, (ObservationGapCode.UNSUPPORTED_FORMAT.value,), ()) == "incompatible"
    assert admission(None, (), ()) == "unadmitted"
    assert set(stream_module.STREAM_ADMISSION_STATES) == {
        "incompatible",
        "partially_understood",
        "structurally_supported",
        "unadmitted",
    }


def test_mapping_upgrade_readmits_a_release_refused_under_the_exact_policy(
    tmp_path: Path,
) -> None:
    """A cursor durably refused under ``codex-obs-stream/1.3.0`` (exact-version policy) replays
    from the header under a fresh generation on upgrade: the previously refused bytes are read
    once, nothing is duplicated, and the compatible profile is persisted (issue #656)."""

    home = tmp_path / "codex-home"
    sessions = home / "sessions" / "2026" / "09" / "08"
    sessions.mkdir(parents=True)
    session_id = "019f8b27-b98e-7061-bbb5-d0b897594de6"
    target = sessions / f"rollout-2026-09-08T12-00-00-{session_id}.jsonl"
    raw = _fixture_bytes(_COMPATIBLE_0153, "relabeled")
    target.write_bytes(raw)
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)
    # The durable refused state the old policy left behind: consumed bytes, zero events.
    store.set_stream_reconcile_state(
        workspace,
        session,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=len(raw),
            event_position=0,
            last_source_commitment=_EMPTY,
            mapping_version="codex-obs-stream/1.3.0",
        ),
        partial=b"",
        call_tools={},
        source_identity=None,
        profile_id=None,
    )

    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )

    assert result["resolved"] is True
    assert result["generation"] == 2
    assert result["profile_id"] == _COMPATIBLE_PROFILE_ID
    assert result["admission"] == "partially_understood"
    assert result["admission_provenance"] == "structural"
    assert result["admission_reasons"] == ()
    assert result["accepted"] == raw.count(b"\n")
    assert result["duplicates"] == 0
    assert result["byte_position"] == len(raw)
    assert result["event_position"] == raw.count(b"\n")
    gaps = result["gaps"]
    assert isinstance(gaps, tuple)
    assert ObservationGapCode.UNSUPPORTED_FORMAT.value not in gaps
    cursor = store.get_stream_cursor(workspace, session)
    assert cursor is not None and cursor.mapping_version == STREAM_MAPPING_VERSION

    # A second pass under the persisted compatible profile reads nothing twice.
    again = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )
    assert again["accepted"] == 0 and again["duplicates"] == 0
    assert again["profile_id"] == _COMPATIBLE_PROFILE_ID
    assert again["admission"] == "partially_understood"
    assert store.stream_profile_for_session(workspace, session) == _COMPATIBLE_PROFILE_ID


def test_reconcile_reports_exact_admission_and_incompatible_header(tmp_path: Path) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions" / "2026" / "09" / "08"
    sessions.mkdir(parents=True)
    session_id = "019f8b27-b98e-7061-bbb5-d0b897594de6"
    target = sessions / f"rollout-2026-09-08T12-00-00-{session_id}.jsonl"
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)

    target.write_bytes(_fixture_bytes(_PAGINATED_0150, "paginated"))
    exact = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )
    assert exact["admission"] == "structurally_supported"
    assert exact["admission_provenance"] == "exact"
    assert exact["profile_id"] == "codex-rollout-jsonl/0.150.1/v1"

    # Rewrite in place with a structurally refused header: incompatible, no profile.
    target.write_bytes(_fixture_bytes(_UNSUPPORTED_0152, "future"))
    refused = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )
    assert refused["admission"] == "incompatible"
    assert refused["admission_provenance"] is None
    assert refused["profile_id"] is None
    assert refused["accepted"] == 0


# --- early observation selection (#687) ------------------------------------------------------


_STREAM_TASK_ID = "tsk_10000000-0000-4000-8000-000000000101"
_STREAM_SESSION_ID = "ses_10000000-0000-4000-8000-000000000102"
_STREAM_WRITER_ID = "wri_10000000-0000-4000-8000-000000000103"
_STREAM_READ_REFERENCE = "clm_10000000-0000-4000-8000-000000000104"


def _selection_stream_fixture(
    tmp_path: Path,
    *,
    rows: tuple[dict[str, object], ...],
    session_id: str = "stream-selection",
) -> tuple[LocalObservationStore, str, str, Path, CodexSessionStreamLocator]:
    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    target = sessions / f"rollout-{session_id}.jsonl"
    target.write_bytes(encode_lines(*rows))
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=session_id,
            yoetz_task_id=_STREAM_TASK_ID,
            yoetz_session_id=_STREAM_SESSION_ID,
            yoetz_writer_id=_STREAM_WRITER_ID,
            last_frontier=None,
        ),
        _state=tmp_path,
    )
    return store, workspace, session, target, CodexSessionStreamLocator(home)


def test_stream_selects_shell_candidate_from_original_arguments_and_flushes_on_boundary(
    tmp_path: Path,
) -> None:
    session_id = "stream-selection-summary"
    rows = (
        session_meta(session_id=session_id),
        function_call(
            name="shell",
            call_id="selection-read",
            arguments='{"command":"ls"}',
        ),
        function_call_output(call_id="selection-read", exit_code=0),
    )
    store, workspace, session, target, locator = _selection_stream_fixture(
        tmp_path, rows=rows, session_id=session_id
    )

    first = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )

    assert first["accepted"] == 3
    assert [row.envelope.event_kind for row in store.list_pending_outbox_rows(workspace)] == [
        "session_meta"
    ]
    account = store.selection_accounting(workspace)
    assert account["buffered_input_count"] == 2
    assert account["buffered_successful_call_count"] == 1

    target.write_bytes(
        target.read_bytes()
        + encode_lines(
            function_call(
                name="apply_patch",
                call_id="selection-mutation",
                arguments='{"patch":"x"}',
            ),
            function_call_output(call_id="selection-mutation", exit_code=0),
        )
    )
    second = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )

    assert second["accepted"] == 2
    rows_out = store.list_pending_outbox_rows(workspace)
    summaries = [
        row.envelope for row in rows_out if row.envelope.event_kind == "RoutineReadSummary"
    ]
    assert len(summaries) == 1
    summary = summaries[0].structural_payload
    assert summary["summary_count"] == 1
    assert summary["input_count"] == 2
    fence = summary["fence"]
    assert type(fence) is str and fence.startswith("sha256:")
    assert summary["provenance"] == "routine_success_summary"
    assert [
        row.envelope.structural_payload.get("action")
        for row in rows_out
        if row.envelope.structural_payload.get("tool_call_id") == "selection-mutation"
    ] == ["function_call", "function_call_output"]


def test_stream_candidate_marker_survives_store_restart(tmp_path: Path) -> None:
    session_id = "stream-selection-restart"
    target_rows = (
        session_meta(session_id=session_id),
        function_call(
            name="shell",
            call_id="restart-read",
            arguments='{"command":"pwd"}',
        ),
    )
    store, workspace, session, target, locator = _selection_stream_fixture(
        tmp_path, rows=target_rows, session_id=session_id
    )
    first = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )
    assert first["event_position"] == 2
    persisted = store.stream_call_tools_for_session(workspace, session, source_generation=1)
    assert persisted["restart-read"].endswith("\x1froutine")

    target.write_bytes(
        target.read_bytes()
        + encode_lines(function_call_output(call_id="restart-read", exit_code=0))
    )
    reopened = LocalObservationStore(_state=tmp_path)
    second = reconcile_session_stream(
        reopened,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )

    assert second["accepted"] == 1
    assert reopened.selection_accounting(workspace)["buffered_successful_call_count"] == 1
    assert not [
        row
        for row in reopened.list_pending_outbox_rows(workspace)
        if row.envelope.event_kind == "RoutineReadSummary"
    ]

    reopened.flush_selected_admission(
        workspace,
        summary_builder=stream_module.build_routine_read_summary,
        force=True,
    )
    assert [
        row.envelope.event_kind
        for row in reopened.list_pending_outbox_rows(workspace)
        if row.envelope.event_kind == "RoutineReadSummary"
    ] == ["RoutineReadSummary"]


def test_stream_failed_routine_output_remains_individual(tmp_path: Path) -> None:
    session_id = "stream-selection-failure"
    rows = (
        session_meta(session_id=session_id),
        function_call(name="shell", call_id="failed-read", arguments='{"command":"ls"}'),
        function_call_output(call_id="failed-read", exit_code=1),
    )
    store, workspace, session, _target, locator = _selection_stream_fixture(
        tmp_path, rows=rows, session_id=session_id
    )

    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )

    assert result["accepted"] == 3
    outbox = store.list_pending_outbox_rows(workspace)
    assert not [row for row in outbox if row.envelope.event_kind == "RoutineReadSummary"]
    assert [
        row.envelope.structural_payload.get("action")
        for row in outbox
        if row.envelope.structural_payload.get("tool_call_id") == "failed-read"
    ] == ["function_call", "function_call_output"]


def test_stream_read_protection_bypasses_summary_and_preserves_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_id = "stream-selection-protected-read"
    rows = (
        session_meta(session_id=session_id),
        function_call(name="shell", call_id="protected-read", arguments='{"command":"ls"}'),
        function_call_output(call_id="protected-read", exit_code=0),
    )
    store, workspace, session, _target, locator = _selection_stream_fixture(
        tmp_path, rows=rows, session_id=session_id
    )
    store.protect_next_reads(workspace, session, _STREAM_READ_REFERENCE)
    consumed: list[tuple[str, object]] = []
    original_consume = LocalObservationStore.consume_read_protection

    def consume(
        selected_store: LocalObservationStore,
        selected_workspace: str,
        selected_session: str,
        envelope: ObservationEnvelope,
    ) -> bool:
        consumed.append((envelope.event_kind, envelope.structural_payload.get("action")))
        return original_consume(selected_store, selected_workspace, selected_session, envelope)

    monkeypatch.setattr(LocalObservationStore, "consume_read_protection", consume)

    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )

    assert result["accepted"] == 3
    outbox = store.list_pending_outbox_rows(workspace)
    assert not [row for row in outbox if row.envelope.event_kind == "RoutineReadSummary"]
    protected = [
        row.envelope
        for row in outbox
        if row.envelope.structural_payload.get("tool_call_id") == "protected-read"
    ]
    assert [(item.event_kind, item.structural_payload.get("action")) for item in protected] == [
        ("PreToolUse", "evidence_linked_read"),
        ("PostToolUse", "evidence_linked_read"),
    ]
    assert [item.structural_payload.get("protection_reference") for item in protected] == [
        _STREAM_READ_REFERENCE,
        _STREAM_READ_REFERENCE,
    ]
    assert consumed == [("PostToolUse", "routine_read")]


def test_stream_unknown_protected_read_stays_individual(tmp_path: Path) -> None:
    session_id = "stream-selection-protected-unknown"
    rows = (
        session_meta(session_id=session_id),
        function_call(name="shell", call_id="protected-unknown", arguments='{"command":"ls"}'),
        response_item(
            {
                "call_id": "protected-unknown",
                "name": "shell",
                "output": "unknown",
                "status": "host_pending",
                "type": "function_call_output",
            }
        ),
    )
    store, workspace, session, _target, locator = _selection_stream_fixture(
        tmp_path, rows=rows, session_id=session_id
    )
    store.protect_next_reads(workspace, session, _STREAM_READ_REFERENCE)

    reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )

    outbox = store.list_pending_outbox_rows(workspace)
    assert not [row for row in outbox if row.envelope.event_kind == "RoutineReadSummary"]
    protected = [
        row.envelope
        for row in outbox
        if row.envelope.structural_payload.get("tool_call_id") == "protected-unknown"
    ]
    assert [item.structural_payload.get("action") for item in protected] == [
        "evidence_linked_read",
        "evidence_linked_read",
    ]
    assert [item.structural_payload.get("protection_reference") for item in protected] == [
        _STREAM_READ_REFERENCE,
        _STREAM_READ_REFERENCE,
    ]


def test_stream_detailed_mode_keeps_individual_materialization_without_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_id = "stream-selection-detailed"
    rows = (
        session_meta(session_id=session_id),
        function_call(name="read", call_id="detailed-read", arguments="{}"),
        function_call_output(call_id="detailed-read", exit_code=0),
    )
    store, workspace, session, _target, locator = _selection_stream_fixture(
        tmp_path, rows=rows, session_id=session_id
    )

    def detailed_pressure(_store: Any, _workspace: Any, _session: Any) -> Any:
        return SimpleNamespace(
            effective_mode=ObservationMode.DETAILED,
            content_allowed=True,
        )

    monkeypatch.setattr(LocalObservationStore, "update_selection_pressure", detailed_pressure)

    reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )

    outbox = store.list_pending_outbox_rows(workspace)
    assert not [row for row in outbox if row.envelope.event_kind == "RoutineReadSummary"]
    detailed = [
        row.envelope
        for row in outbox
        if row.envelope.structural_payload.get("tool_call_id") == "detailed-read"
    ]
    assert [item.structural_payload.get("action") for item in detailed] == [
        "function_call",
        "function_call_output",
    ]
    assert [item.event_kind for item in detailed] == ["PreToolUse", "PostToolUse"]
    assert tuple(
        item.role
        for item in materialize_observation_envelope(detailed[0], task_id=_STREAM_TASK_ID).drafts
    ) == ("action",)
    assert tuple(
        item.role
        for item in materialize_observation_envelope(detailed[1], task_id=_STREAM_TASK_ID).drafts
    ) == ("action", "result")


def test_stream_selection_rejection_replays_exact_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = "stream-selection-replay"
    rows = (
        session_meta(session_id=session_id),
        function_call(name="read", call_id="replay-read", arguments="{}"),
    )
    store, workspace, session, target, locator = _selection_stream_fixture(
        tmp_path, rows=rows, session_id=session_id
    )
    original_commit = LocalObservationStore.commit_selected_admission

    def reject_routine(
        selected_store: LocalObservationStore,
        selected_workspace: str,
        plan: AdmissionPlan,
        *,
        incoming: ObservationEnvelope | None = None,
        newly_observed: bool = False,
        replayable: bool = False,
    ) -> bool:
        if (
            isinstance(incoming, ObservationEnvelope)
            and incoming.structural_payload.get("tool_call_id") == "replay-read"
        ):
            return False
        return original_commit(
            selected_store,
            selected_workspace,
            plan,
            incoming=incoming,
            newly_observed=newly_observed,
            replayable=replayable,
        )

    monkeypatch.setattr(LocalObservationStore, "commit_selected_admission", reject_routine)
    failed = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )
    assert failed["event_position"] == 1
    failed_position = failed["byte_position"]
    assert type(failed_position) is int and failed_position < target.stat().st_size

    monkeypatch.setattr(LocalObservationStore, "commit_selected_admission", original_commit)
    retried = reconcile_session_stream(
        LocalObservationStore(_state=tmp_path),
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=locator,
    )
    assert retried["event_position"] == 2


_DECIDE_SESSION = "hmac-sha256:" + ("d" * 64)
_CMD = "hmac-sha256:" + ("c" * 64)


def _decide_row(
    position: int,
    *,
    hook: bool,
    identity: str,
    call_id: str,
    exit_status: int | None = None,
    commitment: str | None = _CMD,
) -> ObservationEnvelope:
    structural: dict[str, Any] = {"tool_call_id": call_id, "tool_name": "Bash"}
    if commitment is not None:
        structural["command_commitment"] = commitment
    if exit_status is not None:
        structural["exit_status"] = exit_status
    if not hook:
        structural["action"] = "CommandExecution"
    return ObservationEnvelope(
        session_commitment=_DECIDE_SESSION,
        event_kind="PostToolUse" if hook else "item_completed",
        source_identity=identity,
        source=ObservationSource.CODEX_HOOK if hook else ObservationSource.CODEX_SESSION_STREAM,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=position,
            event_position=position,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
        receipt_time=Timestamp("2026-09-29T18:00:00.000Z"),
        structural_payload=JsonObject(structural),
        content_object_refs=(),
        gap_codes=(),
    )


def _decisions(*rows: ObservationEnvelope) -> dict[str, str]:
    return stream_module._rollout_item_decisions(  # pyright: ignore[reportPrivateUsage]
        rows, _DECIDE_SESSION
    )


def test_rollout_item_read_before_its_post_is_decided_by_that_post() -> None:
    """#910: arrival order between a rollout item and its hook post never loses an exit."""

    item = _decide_row(1, hook=False, identity="item-a", call_id="exec-a", exit_status=101)
    unstated = _decide_row(2, hook=True, identity="post-a", call_id="call-a")
    stated = _decide_row(2, hook=True, identity="post-a", call_id="call-a", exit_status=101)
    assert _decisions(item) == {"item-a": "pending"}
    # An outcome-less post makes the earlier item its only outcome; a stated one its copy.
    assert _decisions(item, unstated) == {"item-a": "carrier"}
    assert _decisions(item, stated) == {"item-a": "copy"}
    # The same facts in the other arrival order decide the same way.
    assert _decisions(unstated, item) == {"item-a": "carrier"}
    assert _decisions(stated, item) == {"item-a": "copy"}


def test_rollout_item_decisions_never_change_once_made() -> None:
    """A later post pairs only with a still-pending item, never with one already decided."""

    early = _decide_row(1, hook=True, identity="post-a", call_id="call-a", exit_status=0)
    copy = _decide_row(2, hook=False, identity="item-a", call_id="exec-a", exit_status=0)
    pending = _decide_row(3, hook=False, identity="item-b", call_id="exec-b", exit_status=2)
    late = _decide_row(4, hook=True, identity="post-b", call_id="call-b")
    assert _decisions(early, copy, pending, late) == {"item-a": "copy", "item-b": "carrier"}
    # A stated post with a different exit is not this item's copy; it stays pending.
    other = _decide_row(4, hook=True, identity="post-b", call_id="call-b", exit_status=1)
    assert _decisions(early, copy, pending, other)["item-b"] == "pending"


def test_pending_rollout_items_persist_until_settled(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    other = "hmac-sha256:" + ("e" * 64)
    item_a = _decide_row(1, hook=False, identity="item-a", call_id="exec-a", exit_status=101)
    item_b = _decide_row(2, hook=False, identity="item-b", call_id="exec-b", exit_status=0)
    item_c = replace(
        _decide_row(3, hook=False, identity="item-c", call_id="exec-c"),
        session_commitment=other,
    )
    store.note_pending_rollout_item(workspace, _DECIDE_SESSION, "host-1", item_a)
    store.note_pending_rollout_item(workspace, _DECIDE_SESSION, "host-1", item_b)
    store.note_pending_rollout_item(workspace, other, "host-2", item_c)
    reopened = LocalObservationStore(_state=tmp_path)
    kept = reopened.pending_rollout_items(workspace, _DECIDE_SESSION)
    assert [item.source_identity for item in kept] == ["item-a", "item-b"]
    # The account keeps the item itself, so its outcome survives ring eviction.
    assert kept[0].envelope == item_a and kept[0].codex_session_id == "host-1"
    # Settling is per session and idempotent.
    reopened.settle_pending_rollout_item(workspace, other, "item-a")
    reopened.settle_pending_rollout_item(workspace, _DECIDE_SESSION, "item-a")
    reopened.settle_pending_rollout_item(workspace, _DECIDE_SESSION, "item-a")
    assert [item.source_identity for item in reopened.pending_rollout_items(workspace)] == [
        "item-b",
        "item-c",
    ]


def test_parallel_same_command_items_wait_for_the_open_call() -> None:
    """#910: an outcome-less post never takes a pending item an open same-command call owns."""

    pre_a = replace(
        _decide_row(1, hook=True, identity="pre-a", call_id="call-a"), event_kind="PreToolUse"
    )
    pre_b = replace(
        _decide_row(2, hook=True, identity="pre-b", call_id="call-b"), event_kind="PreToolUse"
    )
    item_b = _decide_row(3, hook=False, identity="item-b", call_id="exec-b", exit_status=0)
    item_a = _decide_row(4, hook=False, identity="item-a", call_id="exec-a", exit_status=1)
    post_a = _decide_row(5, hook=True, identity="post-a", call_id="call-a")
    post_b = _decide_row(6, hook=True, identity="post-b", call_id="call-b", exit_status=0)
    stop = replace(
        _decide_row(7, hook=True, identity="stop", call_id="none", commitment=None),
        event_kind="Stop",
    )
    for order in ((item_b, item_a), (item_a, item_b)):
        rows = (pre_a, pre_b, *order, post_a)
        # B is still open: neither item is A's yet.
        assert _decisions(*rows) == {"item-a": "pending", "item-b": "pending"}
        assert _decisions(*rows, post_b) == {"item-a": "carrier", "item-b": "copy"}
        # Posts first, items after: the same attribution.
        assert _decisions(pre_a, pre_b, post_a, post_b, *order) == {
            "item-a": "carrier",
            "item-b": "copy",
        }
        # B's hook never fires: the turn's end delivers both rather than lose A's failure.
        assert _decisions(*rows, stop) == {"item-a": "carrier", "item-b": "carrier"}
    # The turn's end settles an unclaimed item as a copy only with a stored proof: without one
    # (its post evicted, lost, or stored after Stop) it is delivered unpaired, never dropped.
    assert _decisions(pre_b, item_b, stop) == {"item-b": "unpaired"}
    twin = _decide_row(8, hook=False, identity="item-twin", call_id="exec-twin", exit_status=0)
    assert _decisions(pre_b, post_b, item_b, twin, stop) == {
        "item-b": "copy",
        "item-twin": "copy",
    }
    assert _decisions(pre_b, post_b, item_a, stop) == {"item-a": "unpaired"}
    # An MCP or patch item has no commitment: it stays local as its hooked call's copy.
    mcp = _decide_row(9, hook=False, identity="item-mcp", call_id="exec-mcp", commitment=None)
    assert _decisions(mcp, stop) == {"item-mcp": "copy"}


def test_a_call_open_past_the_ring_still_owns_its_copy() -> None:
    """#910: an evicted ``PreToolUse`` keeps its call open for the pairing replay."""

    item_b = _decide_row(3, hook=False, identity="item-b", call_id="exec-b", exit_status=0)
    post_a = _decide_row(5, hook=True, identity="post-a", call_id="call-a")
    # Without the evicted call, A's outcome-less post would take B's item.
    assert _decisions(item_b, post_a) == {"item-b": "carrier"}
    kept_open = stream_module._rollout_item_decisions(  # pyright: ignore[reportPrivateUsage]
        (item_b, post_a), _DECIDE_SESSION, ((_CMD, "call-a"), (_CMD, "call-b"))
    )
    assert kept_open == {"item-b": "pending"}


def test_0_159_3_calls_pair_with_outputs_on_call_id_not_their_row_ids(tmp_path: Path) -> None:
    """#1038: a 0.159.3 row names itself (``fc_``/``ctc_``) beside the ``call_id`` it shares."""

    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    session_id = "019f9b27-c1de-7a61-9c5e-5d0b8975aa38"
    target = sessions / f"rollout-{session_id}.jsonl"
    target.write_bytes(
        encode_lines(
            session_meta(cli_version="0.159.3", history_mode="paginated"),
            response_item(
                {
                    "arguments": "{}",
                    "call_id": "call_shell_1038",
                    "id": "fc_1038",
                    "name": "shell",
                    "type": "function_call",
                }
            ),
            response_item(
                {
                    "call_id": "call_shell_1038",
                    "exit_code": 0,
                    "id": "fco_1038",
                    "output": "ok",
                    "status": "completed",
                    "type": "function_call_output",
                }
            ),
            item_completed(
                {
                    "arguments": {},
                    "id": "exec-1038-mcp",
                    "result": {"content": []},
                    "server": "yoetz",
                    "status": "completed",
                    "tool": "status",
                    "type": "McpToolCall",
                }
            ),
        )
    )
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)

    reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )

    rows = {
        str(row.envelope.structural_payload.get("action")): row.envelope
        for row in store.list_pending_outbox_rows(workspace)
    }
    call, output = rows["function_call"], rows["function_call_output"]
    assert call.structural_payload["tool_call_id"] == "call_shell_1038"
    assert output.structural_payload["tool_call_id"] == "call_shell_1038"
    assert output.structural_payload.get("tool_name") == "shell"
    assert ObservationGapCode.UNPAIRED_EVENT.value not in output.gap_codes
    batch = materialize_observation_envelope(output, task_id="task_stream_pair_1038")
    assert tuple(item.role for item in batch.drafts) == ("action", "result")
    # A completed item keeps its own id (the one decision 15 compares with a hook call id), and
    # an MCP item keeps its server, as its hook spells it.
    mcp = rows["McpToolCall"]
    assert mcp.structural_payload["tool_call_id"] == "exec-1038-mcp"
    assert mcp.structural_payload["tool_name"] == "mcp__yoetz__status"


@pytest.mark.parametrize(
    ("server", "tool", "expected"),
    [
        (None, "status", "status"),
        ("yoetz", "status", "mcp__yoetz__status"),
        ("github", "status", "mcp__github__status"),
        # A named server the reader cannot fold into ``mcp__<server>__<tool>``: a Yoetz tool name
        # under it is not attributable, any other name keeps its name rules.
        ("ci__bot", "status", None),
        ("_priv", "check", None),
        ("x" * 130, "receipt", None),
        ("ci__bot", "edit_file", "edit_file"),
    ],
    ids=["no-server", "yoetz", "github", "double-underscore", "leading-underscore", "long", "edit"],
)
def test_mcp_item_is_named_by_its_server(
    server: str | None, tool: str, expected: str | None
) -> None:
    """#1038: only an ``McpToolCall`` naming no server keeps a Yoetz tool's bare name."""

    item: dict[str, Any] = {"id": "exec-1038-mcp", "status": "completed", "tool": tool}
    if server is not None:
        item["server"] = server
    item["type"] = "McpToolCall"
    record = CodexParsedRecord(
        1, 0, 200, "event_msg", "McpToolCall", JsonObject(item_completed(item))
    )

    structural, _gaps = stream_module.structural_from_stream_record(record)

    assert structural.get("tool_name") == expected


def test_hook_prompt_row_is_bookkeeping_not_an_unsupported_event(tmp_path: Path) -> None:
    """#1041: the Stop hook's prompt row (``HookPrompt``) is admitted as bookkeeping."""

    path = tmp_path / "session.jsonl"
    path.write_bytes(
        encode_lines(
            session_meta(cli_version="0.159.3", history_mode="paginated"),
            item_completed(
                {
                    "fragments": [{"hook_run_id": "stop-1", "text": "CANARY_HOOK_PROMPT"}],
                    "id": "item_hook_prompt_1",
                    "type": "HookPrompt",
                }
            ),
        )
    )
    advance = _header_selected_reader("hmac-sha256:" + ("e" * 64)).advance(path)
    assert ObservationGapCode.UNSUPPORTED_EVENT.value not in advance.gaps
    assert advance.reason_codes == ()
    prompt = advance.envelopes[-1]
    assert prompt.event_kind == "event_msg"
    assert prompt.structural_payload.get("action") == "HookPrompt"
    assert "tool_name" not in prompt.structural_payload
    assert "CANARY_HOOK_PROMPT" not in json.dumps(dict(prompt.structural_payload))
    descriptions = [
        str(getattr(item.draft.payload, "description", ""))
        for item in materialize_observation_envelope(prompt, task_id=_STREAM_TASK_ID).drafts
    ]
    assert descriptions == ["Opaque observation kind=event_msg"]
