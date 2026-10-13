"""State-file bounds for stream partials and store-stage attribution (#289, #290)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

import yoetz.adapters.integrations.codex_session_stream as stream_mod
import yoetz.adapters.integrations.observation_local as local_mod
from builders.codex_rollout import encode_lines, response_item, session_meta
from yoetz.adapters.integrations.codex_session_stream import (
    STREAM_MAPPING_VERSION,
    SessionStreamReader,
    default_stream_profile,
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
from yoetz.protocol.errors import ProtocolValueError, PublicErrorCode, PublicOperationError

_DROPPED_GAP = "_local_stream_partial_dropped"
_MAX_PARTIAL = local_mod._MAX_STREAM_PARTIAL_BYTES  # pyright: ignore[reportPrivateUsage]


def _envelope(
    *,
    session: str,
    identity: str,
    ordinal: int = 1,
    source: ObservationSource = ObservationSource.CODEX_HOOK,
    gap_codes: tuple[str, ...] = (),
) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=session,
        event_kind="PreToolUse",
        source_identity=identity,
        source=source,
        cursor=ObservationCursor(1, 0, ordinal, f"hmac-sha256:{'ab' * 32}", "codex-obs-hook/1.0.0"),
        receipt_time=Timestamp("2026-01-01T00:00:00.000Z"),
        structural_payload=JsonObject({"tool_name": "shell", "tool_call_id": f"c{ordinal}"}),
        content_object_refs=(),
        gap_codes=gap_codes,
    )


def _consented_store(tmp_path: Path) -> tuple[LocalObservationStore, str, str]:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "sess-partials")
    return store, workspace, session


def _state_json(tmp_path: Path) -> dict[str, object]:
    path = next((tmp_path / "observation" / "workspaces").glob("*.json"))
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def test_cursor_hook_updates_hook_liveness_not_stream_reconcile(tmp_path: Path) -> None:
    store, _workspace, session = _consented_store(tmp_path)

    store.ingest(
        _envelope(
            session=session,
            identity="hook:cursor-live",
            source=ObservationSource.CURSOR_HOOK,
        )
    )

    persisted = _state_json(tmp_path)
    assert isinstance(persisted["last_hook_receipt_mono_ms"], int)
    assert persisted["last_stream_reconcile_mono_ms"] is None


def test_stream_partial_round_trips_within_bound(tmp_path: Path) -> None:
    store, workspace, session = _consented_store(tmp_path)
    partial = b'{"unterminated": tail' * 16
    store.set_stream_partial(workspace, session, partial)
    assert store.get_stream_partial(workspace, session) == partial
    store.set_stream_partial(workspace, session, b"")
    assert store.get_stream_partial(workspace, session) == b""


def test_stream_partial_rejects_non_bytes(tmp_path: Path) -> None:
    store, workspace, session = _consented_store(tmp_path)
    with pytest.raises(ProtocolValueError):
        store.set_stream_partial(workspace, session, cast(bytes, "text"))


def test_oversized_stream_partial_drops_with_gap_instead_of_raising(tmp_path: Path) -> None:
    """An oversized tail must not stall the stream or pin state-file bytes (#289)."""

    store, workspace, session = _consented_store(tmp_path)
    store.set_stream_partial(workspace, session, b"held")
    oversized = b"x" * (_MAX_PARTIAL + 1)

    store.set_stream_partial(workspace, session, oversized)

    assert store.get_stream_partial(workspace, session) == b""
    persisted = _state_json(tmp_path)
    assert _DROPPED_GAP in cast(list[str], persisted["gaps"])
    # The internal marker never leaks to status; it projects as SOURCE_LAG,
    # because the source tail is pending a reread until reconcile catches up.
    gaps = store.status(ObservationStatusQuery(workspace)).gaps
    assert _DROPPED_GAP not in gaps
    assert ObservationGapCode.SOURCE_LAG.value in gaps


def test_recovered_stream_partial_resolves_the_dropped_gap(tmp_path: Path) -> None:
    store, workspace, session = _consented_store(tmp_path)
    store.set_stream_partial(workspace, session, b"y" * (_MAX_PARTIAL + 1))
    assert (
        ObservationGapCode.SOURCE_LAG.value in store.status(ObservationStatusQuery(workspace)).gaps
    )

    store.set_stream_partial(workspace, session, b"reread tail")

    assert store.get_stream_partial(workspace, session) == b"reread tail"
    gaps = store.status(ObservationStatusQuery(workspace)).gaps
    assert ObservationGapCode.SOURCE_LAG.value not in gaps


def test_recovering_one_session_does_not_clear_another_dropped_partial(tmp_path: Path) -> None:
    """The workspace lag remains until every affected session recovers."""

    store, workspace, first = _consented_store(tmp_path)
    second = store.bind_codex_session(workspace, "sess-partials-2")
    store.set_stream_partial(workspace, first, b"a" * (_MAX_PARTIAL + 1))
    store.set_stream_partial(workspace, second, b"b" * (_MAX_PARTIAL + 1))

    store.set_stream_partial(workspace, second, b"recovered")

    gaps = store.status(ObservationStatusQuery(workspace)).gaps
    assert ObservationGapCode.SOURCE_LAG.value in gaps
    persisted = _state_json(tmp_path)
    assert persisted["stream_partial_dropped_sessions"] == [first]

    store.set_stream_partial(workspace, first, b"recovered")
    assert (
        ObservationGapCode.SOURCE_LAG.value
        not in store.status(ObservationStatusQuery(workspace)).gaps
    )


def test_save_sheds_stream_partials_before_envelopes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The eviction ladder drops the read-cache before any durable row (#289)."""

    store, workspace, session = _consented_store(tmp_path)
    for ordinal in range(1, 4):
        store.ingest(_envelope(session=session, identity=f"hook:keep:{ordinal}", ordinal=ordinal))
    store.set_stream_partial(workspace, session, b"a" * 4_096)
    other = store.bind_codex_session(workspace, "sess-partials-2")
    store.set_stream_partial(workspace, other, b"b" * 8_192)
    state_path = next((tmp_path / "observation" / "workspaces").glob("*.json"))
    # Cap below the current size but above what remains once both partials
    # (their base64 forms dominate the overage) are shed.
    monkeypatch.setattr(local_mod, "_MAX_STATE_BYTES", state_path.stat().st_size - 8_192)

    store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)

    reopened = LocalObservationStore(_state=tmp_path)
    # Largest-first shedding stops as soon as the state fits: the big partial
    # is gone, the small one survives untouched.
    assert reopened.get_stream_partial(workspace, other) == b""
    assert reopened.get_stream_partial(workspace, session) == b"a" * 4_096
    persisted = _state_json(tmp_path)
    assert _DROPPED_GAP in cast(list[str], persisted["gaps"])
    # Every envelope survived: partials were shed first and sufficed.
    assert len(cast(list[object], persisted["envelopes"])) == 3
    assert ObservationGapCode.TRUNCATED_PAYLOAD.value not in cast(list[str], persisted["gaps"])


def test_legacy_oversized_partial_is_dropped_on_next_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """States persisted before the bound existed are healed by any later save."""

    store, workspace, session = _consented_store(tmp_path)
    monkeypatch.setattr(local_mod, "_MAX_STREAM_PARTIAL_BYTES", 1 << 30)
    store.set_stream_partial(workspace, session, b"z" * (_MAX_PARTIAL + 1))
    monkeypatch.undo()

    reopened = LocalObservationStore(_state=tmp_path)
    reopened.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)

    assert reopened.get_stream_partial(workspace, session) == b""
    persisted = _state_json(tmp_path)
    assert _DROPPED_GAP in cast(list[str], persisted["gaps"])


def test_partial_bound_is_at_least_the_reader_chunk() -> None:
    """A bound below one read chunk makes long source lines unassemblable (#289).

    The reader holds a line's prefix here across passes. Below one chunk the
    hold is dropped, the next pass rereads the identical chunk, and the cursor
    never advances again for that session.
    """

    assert _MAX_PARTIAL >= stream_mod._MAX_READ_CHUNK  # pyright: ignore[reportPrivateUsage]


def test_stream_drains_a_source_line_longer_than_one_read_chunk(tmp_path: Path) -> None:
    """A held prefix must survive long enough to assemble the line (#289)."""

    store, workspace, session = _consented_store(tmp_path)
    source = tmp_path / "rollout.jsonl"
    chunk = stream_mod._MAX_READ_CHUNK  # pyright: ignore[reportPrivateUsage]
    long_row = response_item(
        {
            "content": [{"text": "z" * (chunk + 40_000), "type": "output_text"}],
            "role": "assistant",
            "type": "message",
        }
    )
    source.write_bytes(encode_lines(session_meta(), long_row))

    cursor = ObservationCursor(1, 0, 0, f"hmac-sha256:{'00' * 32}", STREAM_MAPPING_VERSION)
    for _ in range(4):
        reader = SessionStreamReader(
            session_commitment=session,
            profile=default_stream_profile(),
            cursor=cursor,
            key_material=store.key_material(),
            partial_line=store.get_stream_partial(workspace, session),
        )
        advance = reader.advance(source)
        cursor = advance.cursor
        store.set_stream_cursor(workspace, session, cursor)
        store.set_stream_partial(workspace, session, advance.partial_line)

    assert cursor.byte_position == source.stat().st_size
    assert store.get_stream_partial(workspace, session) == b""


def test_dropped_unterminated_long_line_recovers_when_newline_arrives(tmp_path: Path) -> None:
    """A legal long live line is reread and drained after its terminator appears."""

    store, workspace, session = _consented_store(tmp_path)
    source = tmp_path / "rollout.jsonl"
    chunk = stream_mod._MAX_READ_CHUNK  # pyright: ignore[reportPrivateUsage]
    long_line = encode_lines(session_meta()) + encode_lines(
        response_item(
            {
                "content": [{"text": "z" * (chunk + 40_000), "type": "output_text"}],
                "role": "assistant",
                "type": "message",
            }
        ),
        terminated=False,
    )
    source.write_bytes(long_line)
    cursor = ObservationCursor(1, 0, 0, f"hmac-sha256:{'00' * 32}", STREAM_MAPPING_VERSION)

    first = SessionStreamReader(
        session_commitment=session,
        profile=default_stream_profile(),
        cursor=cursor,
        key_material=store.key_material(),
    ).advance(source)
    assert first.partial_line
    store.set_stream_partial(workspace, session, first.partial_line)

    oversized = SessionStreamReader(
        session_commitment=session,
        profile=default_stream_profile(),
        cursor=first.cursor,
        key_material=store.key_material(),
        partial_line=store.get_stream_partial(workspace, session),
    ).advance(source)
    assert len(oversized.partial_line) > _MAX_PARTIAL
    store.set_stream_partial(workspace, session, oversized.partial_line)
    assert store.get_stream_partial(workspace, session) == b""

    source.write_bytes(long_line + b"\n")
    recovered = SessionStreamReader(
        session_commitment=session,
        profile=default_stream_profile(),
        cursor=oversized.cursor,
        key_material=store.key_material(),
        partial_line=store.get_stream_partial(workspace, session),
    ).advance(source)
    store.set_stream_cursor(workspace, session, recovered.cursor)
    store.set_stream_partial(workspace, session, recovered.partial_line)

    assert recovered.cursor.byte_position == source.stat().st_size
    assert recovered.partial_line == b""
    assert (
        ObservationGapCode.SOURCE_LAG.value
        not in store.status(ObservationStatusQuery(workspace)).gaps
    )


def _force_envelope_eviction(
    store: LocalObservationStore,
    workspace: str,
    session: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    for ordinal in range(1, 12):
        store.ingest(_envelope(session=session, identity=f"hook:evict:{ordinal}", ordinal=ordinal))
    state_path = next((tmp_path / "observation" / "workspaces").glob("*.json"))
    # Below the current size, so the next save must shed durable envelopes.
    monkeypatch.setattr(local_mod, "_MAX_STATE_BYTES", state_path.stat().st_size - 1_024)
    store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)


def test_envelope_eviction_persists_retention_provenance_for_pairing_reconciliation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A size-pressure eviction must block legacy false-gap retirement."""

    store, workspace, session = _consented_store(tmp_path)
    legacy_post_only = replace(
        _envelope(
            session=session,
            identity="hook:legacy-post-only",
            ordinal=1,
            source=ObservationSource.CLAUDE_HOOK,
        ),
        event_kind="PostToolUse",
        structural_payload=JsonObject(
            {
                "capability_profile_id": "claude-code-cli-local-project-2.1.241",
                "tool_call_id": "legacy-call",
            }
        ),
        gap_codes=(ObservationGapCode.UNPAIRED_EVENT.value,),
    )
    true_orphan = replace(
        _envelope(session=session, identity="hook:true-orphan", ordinal=2),
        event_kind="PostToolUse",
        gap_codes=(ObservationGapCode.UNPAIRED_EVENT.value,),
    )
    state = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
    state.envelopes = [legacy_post_only, true_orphan]
    store._note_gap_state(  # pyright: ignore[reportPrivateUsage]
        state, ObservationGapCode.UNPAIRED_EVENT.value
    )
    both_size = len(store._encode_state(workspace, state))  # pyright: ignore[reportPrivateUsage]
    # The eviction records its local-retention reason (tb4n5), so the one-envelope state it
    # leaves carries that reason too.
    measured = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
    measured.envelopes = [legacy_post_only]
    store._note_gap_state(  # pyright: ignore[reportPrivateUsage]
        measured, ObservationGapCode.UNPAIRED_EVENT.value
    )
    store._note_gap_state(  # pyright: ignore[reportPrivateUsage]
        measured,
        local_mod._LOCAL_ENVELOPE_RETENTION_GAP,  # pyright: ignore[reportPrivateUsage]
    )
    store._note_session_gap_state(  # pyright: ignore[reportPrivateUsage]
        measured,
        session,
        local_mod._LOCAL_ENVELOPE_RETENTION_GAP,  # pyright: ignore[reportPrivateUsage]
    )
    measured.envelopes_truncated = True
    one_size = len(store._encode_state(workspace, measured))  # pyright: ignore[reportPrivateUsage]
    state.envelopes = [legacy_post_only, true_orphan]
    cap = one_size + max(64, (both_size - one_size) // 2)
    if cap >= both_size:
        cap = both_size - 1
    monkeypatch.setattr(local_mod, "_MAX_STATE_BYTES", cap)

    def choose_envelope_index(envelopes: list[ObservationEnvelope]) -> int | None:
        return 1 if len(envelopes) > 1 else None

    monkeypatch.setattr(
        store,
        "_fair_envelope_index",
        choose_envelope_index,
    )

    store._save(workspace, state)  # pyright: ignore[reportPrivateUsage]

    persisted = _state_json(tmp_path)
    assert persisted["envelopes_truncated"] is True
    assert len(cast(list[object], persisted["envelopes"])) == 1
    reopened = LocalObservationStore(_state=tmp_path)
    assert (
        ObservationGapCode.UNPAIRED_EVENT.value
        in reopened.status(ObservationStatusQuery(workspace)).gaps
    )
    history = cast(dict[str, dict[str, object]], persisted["gap_history"])
    assert history[ObservationGapCode.UNPAIRED_EVENT.value]["active"] is True


def test_state_bound_eviction_is_local_retention_not_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """tb4n5: shedding local envelope copies cut no delivered payload.

    #310 gave the eviction gap a resolution path; tb4n5 showed the gap itself was the wrong
    name. The shed rows are local copies of accepted inputs, so the eviction is recorded under
    its own local-retention reason and never as ``truncated_payload``.
    """

    store, workspace, session = _consented_store(tmp_path)
    _force_envelope_eviction(store, workspace, session, monkeypatch, tmp_path)
    truncated = ObservationGapCode.TRUNCATED_PAYLOAD.value
    assert truncated not in store.status(ObservationStatusQuery(workspace)).gaps
    retention = store.local_retention(workspace)
    assert isinstance(retention["envelope_ring"], Mapping)
    assert truncated not in store.session_gap_codes(workspace, session)

    # Renewed shedding is retention again, still never truncation.
    monkeypatch.setattr(local_mod, "_MAX_STATE_BYTES", 1_048_576)
    store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)
    _force_envelope_eviction(store, workspace, session, monkeypatch, tmp_path)
    assert truncated not in store.status(ObservationStatusQuery(workspace)).gaps


def test_a_truncation_flag_left_by_an_older_store_clears_once_the_bound_has_headroom(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An upgraded store's retention-era ``truncated_payload`` is not pinned by retention any more.

    Before tb4n5 the ring and the state bound recorded ``truncated_payload`` beside their own
    retention reason, and the retention reason kept the flag active for good. With headroom the
    live flag clears; history keeps the moment it was seen.
    """

    store, workspace, session = _consented_store(tmp_path)
    _force_envelope_eviction(store, workspace, session, monkeypatch, tmp_path)
    truncated = ObservationGapCode.TRUNCATED_PAYLOAD.value
    # The older writer's flag, beside the retention reason that used to pin it.
    store.note_coverage_gap(workspace, truncated)
    assert truncated in store.status(ObservationStatusQuery(workspace)).gaps

    monkeypatch.setattr(local_mod, "_MAX_STATE_BYTES", 1_048_576)
    store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)
    assert truncated not in store.status(ObservationStatusQuery(workspace)).gaps
    persisted = _state_json(tmp_path)
    history = cast(dict[str, dict[str, object]], persisted["gap_history"])
    assert history[truncated]["active"] is False
    assert history[truncated]["first_seen"]
    reopened = LocalObservationStore(_state=tmp_path)
    assert truncated not in reopened.status(ObservationStatusQuery(workspace)).gaps


def test_a_long_session_past_the_ring_bound_reports_no_truncation(tmp_path: Path) -> None:
    """tb4n5: 376-2262 observed rows per attempt crossed the 256-row ring in all 18 attempts."""

    store, workspace, session = _consented_store(tmp_path)
    for ordinal in range(1, 301):
        store.ingest(_envelope(session=session, identity=f"hook:long:{ordinal}", ordinal=ordinal))

    assert len(store.list_envelopes(workspace)) == 256
    assert (
        ObservationGapCode.TRUNCATED_PAYLOAD.value
        not in store.status(ObservationStatusQuery(workspace)).gaps
    )
    assert isinstance(store.local_retention(workspace)["envelope_ring"], Mapping)


def test_a_cut_payload_still_discloses_truncation(tmp_path: Path) -> None:
    """Real clipping keeps its disclosure: the clipped row carries the gap to its ledger record."""

    store, workspace, session = _consented_store(tmp_path)
    store.ingest(
        _envelope(
            session=session,
            identity="hook:cut",
            gap_codes=(ObservationGapCode.TRUNCATED_PAYLOAD.value,),
        )
    )
    (retained,) = store.list_envelopes(workspace)
    assert ObservationGapCode.TRUNCATED_PAYLOAD.value in retained.gap_codes
    history = cast(dict[str, dict[str, object]], _state_json(tmp_path)["gap_history"])
    assert history[ObservationGapCode.TRUNCATED_PAYLOAD.value]["first_seen"]
    assert store.local_retention(workspace) == {"dedup_fence": None, "envelope_ring": None}


def test_pairing_history_does_not_reconcile_after_envelope_eviction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A retained post-only suffix cannot prove an evicted true orphan healed."""

    store, workspace, session = _consented_store(tmp_path)
    store.ingest(
        _envelope(
            session=session,
            identity="hook:legacy-codex-orphan",
            ordinal=1,
            gap_codes=(ObservationGapCode.UNPAIRED_EVENT.value,),
        )
    )
    # Simulate the bounded suffix retaining only a later legacy Claude false
    # positive.  The missing Codex row must keep the active diagnostic honest.
    monkeypatch.setattr(local_mod, "_MAX_ENVELOPES", 1)
    store.ingest(
        _envelope(
            session=session,
            identity="hook:legacy-claude-post-only",
            ordinal=2,
            source=ObservationSource.CLAUDE_HOOK,
            gap_codes=(ObservationGapCode.UNPAIRED_EVENT.value,),
        )
    )

    assert (
        ObservationGapCode.UNPAIRED_EVENT.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )


def test_store_stage_timings_attribute_hydrate_encode_write(tmp_path: Path) -> None:
    """The store accounts its hydrate/encode/write cost for hook timing rows (#290)."""

    seeded, workspace, session = _consented_store(tmp_path)
    seeded.ingest(_envelope(session=session, identity="hook:timed", ordinal=1))

    store = LocalObservationStore(_state=tmp_path)
    assert store.stage_timings_ms == {
        "hydrate": 0.0,
        "encode": 0.0,
        "lock_wait": 0.0,
        "lock_hold": 0.0,
        "write": 0.0,
    }
    store.note_coverage_gap(workspace, ObservationGapCode.SERVICE_UNAVAILABLE.value)
    assert store.stage_timings_ms["hydrate"] > 0.0
    assert store.stage_timings_ms["encode"] > 0.0
    assert store.stage_timings_ms["write"] > 0.0
    # Uncontended acquisition still registers as time spent on the lock (#310).
    assert store.stage_timings_ms["lock_wait"] > 0.0
    # The critical section itself is attributed separately from queueing (#689).
    assert store.stage_timings_ms["lock_hold"] >= store.stage_timings_ms["write"]


def test_stream_profile_round_trips_and_clears(tmp_path: Path) -> None:
    store, workspace, session = _consented_store(tmp_path)
    assert store.stream_profile_for_session(workspace, session) is None
    store.set_stream_profile(workspace, session, "codex-rollout-jsonl/0.150.1/v1")
    assert store.stream_profile_for_session(workspace, session) == "codex-rollout-jsonl/0.150.1/v1"
    assert _state_json(tmp_path)["stream_profiles"] == {
        session: "codex-rollout-jsonl/0.150.1/v1",
    }

    reloaded = LocalObservationStore(_state=tmp_path)
    assert reloaded.stream_profile_for_session(workspace, session) == (
        "codex-rollout-jsonl/0.150.1/v1"
    )
    reloaded.set_stream_profile(workspace, session, None)
    assert reloaded.stream_profile_for_session(workspace, session) is None
    assert "stream_profiles" not in _state_json(tmp_path)


@pytest.mark.parametrize("bad", ["", "/leading", "has space", "x" * 129, "tab\tid"])
def test_stream_profile_rejects_non_token_ids(tmp_path: Path, bad: str) -> None:
    store, workspace, session = _consented_store(tmp_path)
    with pytest.raises(ProtocolValueError, match="invalid_event_value_type"):
        store.set_stream_profile(workspace, session, bad)
    with pytest.raises(ProtocolValueError, match="invalid_event_value_type"):
        store.set_stream_reconcile_state(
            workspace,
            session,
            cursor=ObservationCursor(1, 0, 0, f"hmac-sha256:{'ab' * 32}", "codex-obs-stream/1.3.0"),
            partial=b"",
            call_tools={},
            source_identity=None,
            profile_id=bad,
        )
    assert store.stream_profile_for_session(workspace, session) is None


def test_reconcile_state_persists_profile_atomically_with_cursor(tmp_path: Path) -> None:
    store, workspace, session = _consented_store(tmp_path)
    cursor = ObservationCursor(2, 10, 3, f"hmac-sha256:{'ab' * 32}", "codex-obs-stream/1.3.0")
    store.set_stream_reconcile_state(
        workspace,
        session,
        cursor=cursor,
        partial=b"",
        call_tools={},
        source_identity=None,
        profile_id="codex-rollout-jsonl/0.148.0/v1",
    )
    assert store.stream_profile_for_session(workspace, session) == "codex-rollout-jsonl/0.148.0/v1"
    store.set_stream_reconcile_state(
        workspace,
        session,
        cursor=cursor,
        partial=b"",
        call_tools={},
        source_identity=None,
        profile_id=None,
    )
    assert store.stream_profile_for_session(workspace, session) is None


def test_invalid_persisted_profile_is_dropped_on_load(tmp_path: Path) -> None:
    store, workspace, session = _consented_store(tmp_path)
    store.set_stream_profile(workspace, session, "codex-rollout-jsonl/0.150.1/v1")
    path = next((tmp_path / "observation" / "workspaces").glob("*.json"))
    body = cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))
    body["stream_profiles"] = {session: "not a token", "other": "codex-rollout-jsonl/0.150.1/v1"}
    path.write_text(json.dumps(body), encoding="utf-8")

    reloaded = LocalObservationStore(_state=tmp_path)
    assert reloaded.stream_profile_for_session(workspace, session) is None
    assert reloaded.stream_profile_for_session(workspace, "other") == (
        "codex-rollout-jsonl/0.150.1/v1"
    )


def test_codex_session_lifecycles_report_every_binding_with_its_ended_flag(
    tmp_path: Path,
) -> None:
    """#549: one state read answers the ended question for every bound session."""

    store, workspace, _ = _consented_store(tmp_path)
    live = store.bind_codex_session(workspace, "sess-live")
    ended = store.bind_codex_session(workspace, "sess-ended")
    store.note_session_end(workspace, ended)
    del live

    assert store.codex_session_lifecycles_for_workspace(workspace) == (
        ("sess-ended", True),
        ("sess-live", False),
        ("sess-partials", False),
    )
    assert store.codex_session_lifecycles_for_workspace("hmac-sha256:" + "0" * 64) == ()


def test_prune_codex_session_bindings_removes_only_ended_and_drained_sessions(
    tmp_path: Path,
) -> None:
    """#549: live, pending, quarantined, and corrupt sessions keep their binding."""

    store, workspace, _ = _consented_store(tmp_path)
    kinds = ("live", "clean", "pending", "quarantined", "corrupt")
    commitments = {kind: store.bind_codex_session(workspace, f"sess-{kind}") for kind in kinds}
    for kind in kinds[1:]:
        store.note_session_end(workspace, commitments[kind])
    for kind in ("pending", "quarantined", "corrupt"):
        assert (
            store.enqueue_outbox(
                workspace,
                f"sess-{kind}",
                _envelope(session=commitments[kind], identity=f"hook:{kind}"),
            )
            is None
        )
    assert (
        store.quarantine_outbox_session(
            workspace, "sess-quarantined", ObservationGapCode.MAPPING_MISSING.value
        )
        == 1
    )
    assert (
        store.quarantine_outbox_session(
            workspace, "sess-corrupt", ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value
        )
        == 1
    )
    store.note_frontier_motion(
        workspace,
        "sess-clean",
        from_sequence=1,
        to_sequence=2,
        head_digest="sha256:" + "1" * 64,
        observation_record_count=1,
        task_id="tsk-prune-test",
    )
    everything = tuple(f"sess-{kind}" for kind in kinds) + ("sess-unknown", "")

    assert store.prune_codex_session_bindings(workspace, everything) == ("sess-clean",)

    expected = (
        ("sess-corrupt", True),
        ("sess-live", False),
        ("sess-partials", False),
        ("sess-pending", True),
        ("sess-quarantined", True),
    )
    assert store.codex_session_lifecycles_for_workspace(workspace) == expected
    assert store.peek_frontier_motion(workspace, "sess-clean") is None
    # The ended-unmapped quarantine path still resolves every retained session.
    assert store.codex_session_ended(workspace, "sess-pending") is True
    assert store.codex_session_ended(workspace, "sess-quarantined") is True
    assert store.codex_session_ended(workspace, "sess-clean") is False
    # Pruning is a persisted change to the existing binding map, not a new shape.
    raw = _state_json(tmp_path)
    bindings = cast(dict[str, str], raw["codex_session_bindings"])
    assert sorted(bindings) == [session_id for session_id, _ in expected]
    reloaded = LocalObservationStore(_state=tmp_path)
    assert reloaded.codex_session_lifecycles_for_workspace(workspace) == expected
    # A second prune with nothing eligible is a no-op.
    assert store.prune_codex_session_bindings(workspace, everything) == ()

    # Once the pending lane drains, the same request prunes that session too.
    (row,) = store.list_pending_outbox_rows(workspace, codex_session_id="sess-pending")
    assert store.acknowledge_outbox_row(workspace, row) is True
    assert store.prune_codex_session_bindings(workspace, everything) == ("sess-pending",)


def test_pruned_binding_resumes_with_generation_continuity(tmp_path: Path) -> None:
    """#549: a resumed session re-binds on its next hook and keeps its generation counter."""

    store, workspace, _ = _consented_store(tmp_path)
    commitment = store.bind_codex_session(workspace, "sess-resumed")
    assert store.begin_session_generation(workspace, commitment) == 1
    store.note_session_end(workspace, commitment)
    assert store.prune_codex_session_bindings(workspace, ("sess-resumed",)) == ("sess-resumed",)
    assert store.codex_session_ended(workspace, "sess-resumed") is False
    assert store.bind_codex_session(workspace, "sess-resumed") == commitment
    # Bound again but not yet restarted: still the ended generation, exactly as
    # before pruning, until SessionStart advances it under the lifecycle lock.
    assert store.codex_session_ended(workspace, "sess-resumed") is True
    assert store.begin_session_generation(workspace, commitment) == 2
    assert store.codex_session_ended(workspace, "sess-resumed") is False


def test_codex_binding_capacity_fails_closed_and_reclaims_only_terminal_lanes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Raw child bindings stay bounded without dropping active accepted lanes."""

    monkeypatch.setattr(local_mod, "_MAX_CODEX_SESSION_BINDINGS", 2)
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    first = store.bind_codex_session(workspace, "sess-binding-first")
    store.bind_codex_session(workspace, "sess-binding-second")

    with pytest.raises(PublicOperationError) as raised:
        store.bind_codex_session(workspace, "sess-binding-third")
    assert raised.value.code is PublicErrorCode.LIMIT_EXCEEDED
    assert raised.value.retryable is True
    assert store.codex_sessions_for_workspace(workspace) == (
        "sess-binding-first",
        "sess-binding-second",
    )

    # A durable terminal mark is enough to make one lane reclaimable. The
    # binding itself is pruned atomically with the subsequent new bind; an
    # active lane is never selected by the capacity guard.
    store.note_session_end(workspace, first)
    assert store.bind_codex_session(workspace, "sess-binding-third")
    assert store.codex_sessions_for_workspace(workspace) == (
        "sess-binding-second",
        "sess-binding-third",
    )
