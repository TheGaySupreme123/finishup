"""A Codex generation bump never costs a command its recorded outcome (#1027, tb4n3 N3-7).

A Codex ``SessionStart`` advances the hook generation (``compact`` after a context compaction,
``resume``, ``clear``) while the session stream keeps the rollout file's generation. The
coordinator therefore re-keys a stream command completion to the hook call's generation (#1019).
tb4n3 showed that re-keying was applied after the completion's captured-content manifests had been
looked up under the *stream's* generation: a hook post that carried captured output committed a
role set (captured evidence plus result) the contentless stream completion could not reconstruct,
so the completion was appended as a new operation whose result event id the hook post already
held. The ledger refused it as ``EVENT_INVALID``, the drain quarantined it as ``ledger_rejected``
and every later command stayed ``unknown`` (183 outcomes in 7 of 7 compacted attempts).

These tests drive the real coordinator, local observation store and task ledger from real hook
payloads and rollout lines (``builders.codex_replay``), deliver the rows of the call under test in
both arrival orders, and assert at the ledger: no refused row, no quarantine, exactly one action
per call, the stream's explicit outcome reaching it, and nothing counted twice.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import replace
from typing import Any, Literal, cast

import pytest

from builders.codex_replay import (
    Recorder,
    Replay,
    build_coordinator,
    command_execution,
    compact,
    replay_cell,  # noqa: F401  # pyright: ignore[reportUnusedImport]  (registers the ``replay`` fixture)
    session_start,
    sweep_all,
)
from finishup.application.observation_drain import ObservationOutboxSweeper
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EvidenceRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from finishup.domain.observation import (
    ObservationEnvelope,
    ObservationIngestRequest,
    ObservationSource,
)
from finishup.kernel.task_facts import EDITED_AFTER_LAST_VERIFICATION_GAP, task_fact_signals

type Bump = Literal["compact", "resume", "clear"]
type Order = Literal["pre_post_stream", "pre_stream_post"]

_TEST_COMMAND = "python -m pytest -q"
_OUTCOME_LESS_RESPONSE = json.dumps(
    {
        "chunk_id": "c1",
        "original_token_count": 0,
        "output": "public synthetic output",
        "session_id": 3,
        "wall_time_seconds": 10.0,
    }
)


def _bump(cell: Replay, source: Bump) -> None:
    """One generation bump the way Codex fires it; the rollout file is never rotated."""

    if source == "compact":
        compact(cell)
    else:
        cell.hook("SessionStart", source=source)


def _run_call(
    cell: Replay, call: str, exit_code: int, timestamp: str, command: str = _TEST_COMMAND
) -> None:
    """A nested command whose hook post states no exit (its process outlived the yield window).

    The rollout item for the call is written between the two hooks, as the host does, so the
    post's reconcile reads it: the item becomes the carrier of the outcome the post lacks.
    """

    tool_input = {"command": command}
    cell.hook("PreToolUse", tool_name="Bash", tool_use_id=call, tool_input=tool_input)
    cell.append(command_execution(call, command, exit_code, timestamp))
    cell.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id=call,
        tool_input=tool_input,
        tool_response=_OUTCOME_LESS_RESPONSE,
    )


def _edit(cell: Replay, call: str, path: str) -> None:
    patch = {"command": f"*** Begin Patch\n*** Update File: {path}\n@@\n-a\n+b\n*** End Patch"}
    cell.hook("PreToolUse", tool_name="apply_patch", tool_use_id=call, tool_input=patch)
    cell.hook(
        "PostToolUse",
        tool_name="apply_patch",
        tool_use_id=call,
        tool_input=patch,
        tool_response=f"Exit code: 0\nWall time: 0.1 seconds\nOutput:\nSuccess. Updated:\nM {path}\n",
    )


async def _deliver_in_order(cell: Replay, order: Order, call: str, *, capture: bool) -> Recorder:
    """Deliver every pending row, but the rows of ``call`` in the chosen arrival order.

    Rows of other calls go first in outbox order. The call's pre/post/stream rows are then
    ingested directly (the outbox is FIFO, but the service ingests whichever row a hook process
    hands it first, and a retried post can follow its stream copy); the final sweep re-delivers
    them, which must be a no-op duplicate.
    """

    rows = cell.store.list_pending_outbox_rows(cell.commitment)

    def role(index: int) -> str | None:
        envelope = rows[index].envelope
        if envelope.structural_payload.get("tool_call_id") != call:
            return None
        if envelope.source is ObservationSource.CODEX_SESSION_STREAM:
            return "stream"
        return {"PreToolUse": "pre", "PostToolUse": "post"}.get(envelope.event_kind)

    by_role = {role(index): index for index in range(len(rows)) if role(index) is not None}
    assert set(by_role) == {"pre", "post", "stream"}, by_role
    first = [index for index in range(len(rows)) if role(index) is None]
    names = ("pre", "post", "stream") if order == "pre_post_stream" else ("pre", "stream", "post")
    recorder = Recorder(build_coordinator(cell), capture_hook_output=capture)
    for index in [*first, *(by_role[name] for name in names)]:
        row = rows[index]
        await recorder.ingest_request(
            ObservationIngestRequest(codex_session_id=row.codex_session_id, envelope=row.envelope)
        )
    return recorder


def _ledger_calls(cell: Replay) -> dict[str, list[tuple[ResultOutcome, int | None]]]:
    """Per command action: every recorded result, in ledger order."""

    actions = {
        str(cast(ActionRecordedPayload, row.payload).action_id)
        for row in cell.rows("action_recorded")
        if cast(ActionRecordedPayload, row.payload).action_kind is ActionKind.COMMAND
    }
    calls: dict[str, list[tuple[ResultOutcome, int | None]]] = {key: [] for key in actions}
    for row in cell.rows("result_recorded"):
        payload = cast(ResultRecordedPayload, row.payload)
        if str(payload.action_id) in calls:
            calls[str(payload.action_id)].append((payload.outcome, payload.exit_status))
    return calls


def _evidence_count(cell: Replay) -> int:
    return len(
        [cast(EvidenceRecordedPayload, row.payload) for row in cell.rows("evidence_recorded")]
    )


def _facts(cell: Replay) -> set[str]:
    state = cell.ledger._state
    return set(task_fact_signals(state.projection, state.records).codes)


@pytest.mark.anyio
@pytest.mark.parametrize("capture", [False, True], ids=["contentless-hook", "captured-hook-post"])
@pytest.mark.parametrize("order", ["pre_post_stream", "pre_stream_post"])
@pytest.mark.parametrize("source", ["compact", "resume", "clear"])
async def test_stream_completion_after_a_generation_bump_reaches_its_hook_call(
    replay: Replay, source: Bump, order: Order, capture: bool
) -> None:
    """N3-7: the stream's exit status lands on the one action the hook recorded, nothing refused."""

    session_start(replay)
    await sweep_all(replay, capture_hook_output=capture)
    _run_call(replay, "call_before", 1, "2026-09-29T18:00:10.000Z")
    await sweep_all(replay, capture_hook_output=capture)
    _bump(replay, source)
    await sweep_all(replay, capture_hook_output=capture)

    _run_call(replay, "call_after", 0, "2026-09-29T18:05:10.000Z")
    delivered = await _deliver_in_order(replay, order, "call_after", capture=capture)
    assert delivered.refused == [], delivered.refused
    # The re-delivery of the very same rows is a duplicate, never a second record.
    results_before = _ledger_calls(replay)
    evidence_before = _evidence_count(replay)
    swept = await sweep_all(replay, capture_hook_output=capture)
    assert swept.refused == [], swept.refused

    assert replay.store.list_quarantine(replay.commitment) == ()
    calls = _ledger_calls(replay)
    assert len(calls) == 2, calls  # one action per host call, before and after the bump
    for results in calls.values():
        assert any(outcome is not ResultOutcome.UNKNOWN for outcome, _ in results), results
    flat = [fact for results in calls.values() for fact in results]
    assert (ResultOutcome.FAILURE, 1) in flat and (ResultOutcome.SUCCESS, 0) in flat
    # Nothing is counted twice: each call keeps at most its hook row plus one explicit outcome.
    assert all(len(results) <= 2 for results in calls.values()), calls
    assert calls == results_before
    assert _evidence_count(replay) == evidence_before


@pytest.mark.anyio
@pytest.mark.parametrize("capture", [False, True], ids=["contentless-hook", "captured-hook-post"])
async def test_green_post_compaction_run_after_an_edit_clears_the_stale_edit_fact(
    replay: Replay, capture: bool
) -> None:
    """N3-7 consequence: a verification run after the last edit is seen once compaction passed.

    The edit lands after the last pre-compaction test run, so the fact holds; the green run after
    the compaction (hook post without an exit, outcome carried by the rollout item) clears it and
    reaches the ledger as a success rather than an unknown.
    """

    session_start(replay)
    _run_call(replay, "call_first", 0, "2026-09-29T18:00:10.000Z")
    await sweep_all(replay, capture_hook_output=capture)
    _edit(replay, "call_patch", "src/public.py")
    await sweep_all(replay, capture_hook_output=capture)
    assert EDITED_AFTER_LAST_VERIFICATION_GAP in _facts(replay)

    compact(replay)
    await sweep_all(replay, capture_hook_output=capture)
    _run_call(replay, "call_green", 0, "2026-09-29T18:05:10.000Z")
    swept = await sweep_all(replay, capture_hook_output=capture)

    assert swept.refused == [], swept.refused
    assert replay.store.list_quarantine(replay.commitment) == ()
    assert EDITED_AFTER_LAST_VERIFICATION_GAP not in _facts(replay)
    green = [
        results
        for results in _ledger_calls(replay).values()
        if (ResultOutcome.SUCCESS, 0) in results
    ]
    assert len(green) == 2  # the pre-compaction run and the post-compaction run, both success


@pytest.mark.anyio
@pytest.mark.parametrize("capture", [False, True], ids=["contentless-hook", "captured-hook-post"])
async def test_failed_post_compaction_run_is_visible_not_unknown(
    replay: Replay, capture: bool
) -> None:
    """N3-7 harm: a failing post-compaction test run must not stay ``unknown`` in the ledger."""

    session_start(replay)
    await sweep_all(replay, capture_hook_output=capture)
    compact(replay)
    await sweep_all(replay, capture_hook_output=capture)
    for number, exit_code in enumerate((2, 1, 0)):
        call = f"call_run{number}"
        _run_call(replay, call, exit_code, f"2026-09-29T18:05:{number}0.000Z")
    swept = await sweep_all(replay, capture_hook_output=capture)

    assert swept.refused == [], swept.refused
    explicit = sorted(
        fact
        for results in _ledger_calls(replay).values()
        for fact in results
        if fact[0] is not ResultOutcome.UNKNOWN
    )
    assert explicit == [
        (ResultOutcome.FAILURE, 1),
        (ResultOutcome.FAILURE, 2),
        (ResultOutcome.SUCCESS, 0),
    ]


@pytest.mark.anyio
async def test_stream_completion_with_no_hook_call_keeps_its_own_generation(
    replay: Replay,
) -> None:
    """The guard stays closed: a completion no hook recorded is its own action, nothing refused."""

    session_start(replay)
    await sweep_all(replay, capture_hook_output=True)
    compact(replay)
    replay.append(command_execution("call_unhooked", _TEST_COMMAND, 0, "2026-09-29T18:05:10.000Z"))
    replay.hook("Stop", last_assistant_message="done", stop_hook_active=False)
    swept = await sweep_all(replay, capture_hook_output=True)

    assert swept.refused == [], swept.refused
    assert replay.store.list_quarantine(replay.commitment) == ()


def _all_pending(cell: Replay) -> Sequence[object]:
    return cell.store.list_pending_outbox_rows(cell.commitment)


@pytest.mark.anyio
async def test_sweeper_drains_a_post_compaction_session_with_no_rejections(
    replay: Replay,
) -> None:
    """The service sweeper (not a hand-driven delivery) leaves nothing pending or refused."""

    session_start(replay)
    compact(replay)
    for number in range(4):
        call = f"call_sweep{number}"
        _run_call(replay, call, number % 2, f"2026-09-29T18:05:{number}0.000Z")
    recorder = Recorder(build_coordinator(replay), capture_hook_output=True)
    sweeper = ObservationOutboxSweeper(replay.store, recorder)
    try:
        for _ in range(8):
            if (await sweeper.sweep()).attempted == 0:
                break
    finally:
        sweeper.close()
    assert recorder.refused == []
    assert not _all_pending(replay)
    assert replay.store.list_quarantine(replay.commitment) == ()


async def _ingest_rows(cell: Replay, recorder: Recorder, call: str, roles: Sequence[str]) -> None:
    """Ingest the pending ``pre``/``post``/``stream`` rows of ``call`` in the given order."""

    rows = cell.store.list_pending_outbox_rows(cell.commitment)
    found: dict[str, ObservationIngestRequest] = {}
    for row in rows:
        envelope = row.envelope
        if envelope.structural_payload.get("tool_call_id") != call:
            continue
        name = (
            "stream"
            if envelope.source is ObservationSource.CODEX_SESSION_STREAM
            else {"PreToolUse": "pre", "PostToolUse": "post"}.get(envelope.event_kind)
        )
        if name is not None:
            found[name] = ObservationIngestRequest(
                codex_session_id=row.codex_session_id, envelope=envelope
            )
    for name in roles:
        await recorder.ingest_request(found[name])


@pytest.mark.anyio
@pytest.mark.parametrize("bumped", [False, True], ids=["same-generation", "after-compaction"])
async def test_a_copy_whose_content_manifests_are_gone_is_a_duplicate_not_a_refusal(
    replay: Replay, bumped: bool
) -> None:
    """Defence in depth: events the ledger holds make a delivery a duplicate, whatever its shape.

    The hook post committed with captured output. The task store later lost that call's content
    manifests (a pruned or reclaimed capture), so the stream copy can no longer reconstruct the
    hook post's role set. Its event ids are all committed, so the ledger would refuse it as
    ``EVENT_INVALID`` and the drain quarantine it as ``ledger_rejected``; it is classified as a
    duplicate instead and its explicit outcome still reaches the recorded action.
    """

    session_start(replay)
    await sweep_all(replay, capture_hook_output=True)
    if bumped:
        compact(replay)
        await sweep_all(replay, capture_hook_output=True)
    _run_call(replay, "call_lost", 2, "2026-09-29T18:05:10.000Z")
    recorder = Recorder(build_coordinator(replay), capture_hook_output=True)
    await _ingest_rows(replay, recorder, "call_lost", ("pre", "post"))
    replay.task_store._db.execute("DELETE FROM observation_content_manifests")
    await _ingest_rows(replay, recorder, "call_lost", ("stream",))

    assert recorder.refused == [], recorder.refused
    assert replay.store.list_quarantine(replay.commitment) == ()
    (results,) = _ledger_calls(replay).values()
    assert results == [(ResultOutcome.UNKNOWN, None), (ResultOutcome.FAILURE, 2)]
    # Redelivering the stream copy changes nothing: the correction is recorded exactly once.
    await _ingest_rows(replay, recorder, "call_lost", ("stream", "post"))
    assert recorder.refused == [], recorder.refused
    assert list(_ledger_calls(replay).values()) == [results]


@pytest.mark.anyio
async def test_a_refusal_after_the_commit_check_is_still_classified_as_a_duplicate(
    replay: Replay, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A delivery that commits between the duplicate check and the append is not quarantined.

    The first committed-events read answers as the ledger looked before that delivery; the
    append is then refused for the event ids it holds, and the refusal is re-read.
    """

    session_start(replay)
    await sweep_all(replay, capture_hook_output=True)
    _run_call(replay, "call_race", 1, "2026-09-29T18:05:10.000Z")
    recorder = Recorder(build_coordinator(replay), capture_hook_output=True)
    await _ingest_rows(replay, recorder, "call_race", ("pre", "post"))
    replay.task_store._db.execute("DELETE FROM observation_content_manifests")
    real = replay.ledger.committed_event_ids
    reads: list[int] = []

    async def stale_first_read(event_ids: Sequence[str]) -> frozenset[str]:
        reads.append(len(reads))
        return frozenset() if len(reads) == 1 else await real(event_ids)

    monkeypatch.setattr(replay.ledger, "committed_event_ids", stale_first_read)
    await _ingest_rows(replay, recorder, "call_race", ("stream",))

    assert len(reads) >= 2
    assert recorder.refused == [], recorder.refused
    assert replay.store.list_quarantine(replay.commitment) == ()
    (results,) = _ledger_calls(replay).values()
    assert results == [(ResultOutcome.UNKNOWN, None), (ResultOutcome.FAILURE, 1)]


def _post_only_envelope(
    cell: Replay, source: ObservationSource, *, corr: str | None
) -> ObservationEnvelope:
    """A Claude Code or Cursor ordinary-profile post: post-only, one call id (or none)."""

    from finishup.domain.observation import ObservationCursor
    from finishup.domain.observation_profiles import (
        CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    )
    from finishup.domain.values import JsonObject, Timestamp

    profile = (
        CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
        if source is ObservationSource.CLAUDE_HOOK
        else CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
    )
    structural: dict[str, object] = {
        "tool_name": "Bash",
        "capability_profile_id": profile,
        "exit_status": 0,
    }
    if corr is not None:
        structural["tool_call_id"] = corr
    return ObservationEnvelope(
        session_commitment=cell.session,
        event_kind="PostToolUse",
        source_identity=f"{source.value}:post:{corr}",
        source=source,
        cursor=ObservationCursor(1, 0, 1, f"hmac-sha256:{'ab' * 32}", "obs/1.0.0"),
        receipt_time=Timestamp("2026-01-01T00:00:00.000Z"),
        structural_payload=JsonObject(structural),
        content_object_refs=(),
        gap_codes=(),
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "source",
    [ObservationSource.CLAUDE_HOOK, ObservationSource.CURSOR_HOOK],
    ids=["claude", "cursor"],
)
async def test_post_only_hosts_get_the_same_duplicate_classification(
    replay: Replay, source: ObservationSource
) -> None:
    """tb4n3 N3-7 item 4: Claude Code and Cursor have no generation alignment to collide with.

    They never re-key an identity, so the alignment shape cannot occur. The general shape, a
    delivery whose role set cannot be reconstructed but whose event ids the ledger holds, can, and
    the classification is host-neutral for a post that names its call. A post with no call id
    mints ids from its source identity, which another call can reuse, so the same collision there
    stays a refusal (#560).
    """

    from types import SimpleNamespace

    from finishup.application.observation_coordinator import _AlreadyCommitted
    from finishup.application.observation_materialize import materialize_observation_envelope
    from finishup.protocol.errors import PublicErrorCode, PublicOperationError

    coordinator = build_coordinator(replay)
    command: Any = SimpleNamespace(
        session_id=replay.mapping.finishup_session_id, writer_id=replay.mapping.finishup_writer_id
    )
    runtime = await coordinator.runtime.route(command)  # type: ignore[attr-defined]

    async def reshaped_copy(corr: str | None) -> object:
        envelope = _post_only_envelope(replay, source, corr=corr)
        batch = materialize_observation_envelope(envelope, task_id=replay.task_id)
        assert batch.skip_reason is None and len(batch.drafts) >= 1
        first = await coordinator._append_materialized(runtime, envelope, batch)
        assert isinstance(first, tuple)
        # The same events under a different role set: what a lost or pruned content manifest does.
        renamed = replace(
            batch,
            drafts=tuple(replace(item, role=f"{item.role}_reshaped") for item in batch.drafts),
        )
        return await coordinator._append_materialized(runtime, envelope, renamed)

    assert isinstance(await reshaped_copy("call-posted"), _AlreadyCommitted)
    with pytest.raises(PublicOperationError) as refused:
        await reshaped_copy(None)
    assert refused.value.code is PublicErrorCode.EVENT_INVALID


def _stated_post(cell: Replay, call: str, exit_code: int) -> None:
    """A hook ``PostToolUse`` that states the call's exit status."""

    tool_input = {"command": _TEST_COMMAND}
    cell.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id=call,
        tool_input=tool_input,
        tool_response=json.dumps(
            {"chunk_id": "s1", "exit_code": exit_code, "output": "public synthetic output"}
        ),
    )


def _pending_hook_post(cell: Replay, call: str) -> Any:
    """The undelivered outbox row of the call's hook ``PostToolUse``."""

    return next(
        row
        for row in cell.store.list_pending_outbox_rows(cell.commitment)
        if row.envelope.event_kind == "PostToolUse"
        and row.envelope.structural_payload.get("tool_call_id") == call
    )


def _hook_post_copy(
    cell: Replay, call: str, *, exit_status: int, row: Any | None = None
) -> ObservationIngestRequest:
    """A second delivery of the call's committed hook post, stating ``exit_status``.

    Same host call and generation (so the same event ids), a different source identity (a separate
    delivery), and no content: what a re-fired or retried post looks like once its manifests are
    gone. ``row`` is the post's outbox row when it was captured before a sweep delivered it.
    """

    from finishup.domain.values import JsonObject

    source_row: Any = row if row is not None else _pending_hook_post(cell, call)
    payload = dict(source_row.envelope.structural_payload)
    payload["exit_status"] = exit_status
    copy = replace(
        source_row.envelope,
        source_identity=f"hook:copy:{call}:{exit_status}",
        structural_payload=JsonObject(payload),
    )
    return ObservationIngestRequest(codex_session_id=source_row.codex_session_id, envelope=copy)


async def _committed_success_then_lost_manifests(cell: Replay, call: str) -> Recorder:
    """A captured hook post stating exit 0 is committed; the call's content manifests are then gone."""

    session_start(cell)
    await sweep_all(cell, capture_hook_output=True)
    cell.hook(
        "PreToolUse", tool_name="Bash", tool_use_id=call, tool_input={"command": _TEST_COMMAND}
    )
    _stated_post(cell, call, 0)
    recorder = Recorder(build_coordinator(cell), capture_hook_output=True)
    await _ingest_rows(cell, recorder, call, ("pre", "post"))
    assert recorder.refused == []
    cell.task_store._db.execute("DELETE FROM observation_content_manifests")
    return recorder


@pytest.mark.anyio
async def test_a_contentless_hook_copy_stating_the_same_outcome_is_a_duplicate(
    replay: Replay,
) -> None:
    await _committed_success_then_lost_manifests(replay, "call_same")
    contentless = Recorder(build_coordinator(replay), capture_hook_output=False)
    await contentless.ingest_request(_hook_post_copy(replay, "call_same", exit_status=0))

    assert contentless.refused == [], contentless.refused
    (results,) = _ledger_calls(replay).values()
    assert results == [(ResultOutcome.SUCCESS, 0)]


@pytest.mark.anyio
async def test_a_contentless_hook_copy_contradicting_the_committed_outcome_is_still_refused(
    replay: Replay,
) -> None:
    """Codex review of #1027: event ids say same call, not same outcome.

    A hook copy has no outcome correction to carry a difference, so the duplicate classification
    must not swallow it: the ledger's refusal and its quarantine stand, and the committed
    outcome is untouched.
    """

    await _committed_success_then_lost_manifests(replay, "call_contradiction")
    contentless = Recorder(build_coordinator(replay), capture_hook_output=False)
    await contentless.ingest_request(_hook_post_copy(replay, "call_contradiction", exit_status=1))

    assert [item[2:] for item in contentless.refused] == [("rejected", "ledger_rejected")]
    (results,) = _ledger_calls(replay).values()
    assert results == [(ResultOutcome.SUCCESS, 0)]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "copy_exit", [0, 1], ids=["agrees-with-correction", "contradicts-correction"]
)
async def test_a_hook_copy_is_judged_against_the_stream_correction_the_ledger_already_holds(
    replay: Replay, copy_exit: int
) -> None:
    """Codex review of #1027: the ledger's outcome for a call is its original result plus the
    stream correction linked to its action. A contentless hook copy stating the corrected outcome
    is a duplicate; one stating another outcome is refused."""

    session_start(replay)
    await sweep_all(replay, capture_hook_output=True)
    _run_call(replay, "call_corrected", 0, "2026-09-29T18:05:10.000Z")
    post_row = _pending_hook_post(replay, "call_corrected")
    await sweep_all(replay, capture_hook_output=True)  # hook UNKNOWN (captured) + stream success
    (committed,) = _ledger_calls(replay).values()
    assert committed == [(ResultOutcome.UNKNOWN, None), (ResultOutcome.SUCCESS, 0)]
    replay.task_store._db.execute("DELETE FROM observation_content_manifests")
    contentless = Recorder(build_coordinator(replay), capture_hook_output=False)
    await contentless.ingest_request(
        _hook_post_copy(replay, "call_corrected", exit_status=copy_exit, row=post_row)
    )

    if copy_exit == 0:
        assert contentless.refused == [], contentless.refused
    else:
        assert [item[2:] for item in contentless.refused] == [("rejected", "ledger_rejected")]
    (after,) = _ledger_calls(replay).values()
    assert after == committed


@pytest.mark.anyio
async def test_a_stream_copy_contradicting_the_committed_outcome_is_recorded_as_a_conflict(
    replay: Replay,
) -> None:
    """The stream copy is a duplicate by event ids, and its differing outcome is not lost: the
    correction records it beside the hook's, flagged as a dedup conflict."""

    from finishup.adapters.integrations.codex_session_stream import STREAM_MAPPING_VERSION
    from finishup.domain.observation import ObservationCursor
    from finishup.domain.values import JsonObject

    await _committed_success_then_lost_manifests(replay, "call_conflict")
    rows = replay.store.list_pending_outbox_rows(replay.commitment)
    hook_post = next(
        row.envelope
        for row in rows
        if row.envelope.event_kind == "PostToolUse"
        and row.envelope.structural_payload.get("tool_call_id") == "call_conflict"
    )
    payload = dict(hook_post.structural_payload)
    payload.update({"exit_status": 1, "action": "CommandExecution"})
    stream_copy = replace(
        hook_post,
        source=ObservationSource.CODEX_SESSION_STREAM,
        event_kind="item_completed",
        source_identity="stream:conflicting-copy",
        structural_payload=JsonObject(payload),
        cursor=ObservationCursor(
            hook_post.cursor.source_generation,
            1_000_000,
            1_000_000,
            f"hmac-sha256:{'cd' * 32}",
            STREAM_MAPPING_VERSION,
        ),
    )
    recorder = Recorder(build_coordinator(replay), capture_hook_output=False)
    await recorder.ingest_request(
        ObservationIngestRequest(codex_session_id=rows[0].codex_session_id, envelope=stream_copy)
    )

    assert recorder.refused == [], recorder.refused
    (results,) = _ledger_calls(replay).values()
    assert results == [(ResultOutcome.SUCCESS, 0), (ResultOutcome.FAILURE, 1)]
