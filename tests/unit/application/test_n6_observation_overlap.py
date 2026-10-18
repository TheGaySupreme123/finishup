"""Recorded-rollout-shaped hook/stream deliveries can enrich the same immutable call."""

# pyright: reportPrivateUsage=false
from __future__ import annotations

import asyncio
import io
import json
from collections.abc import Awaitable, Callable
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from builders.codex_replay import Replay as CodexReplay
from builders.codex_replay import (
    replay_cell,  # noqa: F401  # pyright: ignore[reportUnusedImport]  (registers the ``replay`` fixture)
    rollout_row,
    session_start,
    sweep_all,
)
from finishup.adapters.integrations.codex_session_stream import SessionStreamReader
from finishup.adapters.integrations.observation_local import STREAM_MAPPING_VERSION
from finishup.application.missing_for_assessment import plan_review_follow_up
from finishup.application.semantic_content import resolve_captured_semantic_content
from finishup.cli.observe_hooks import ServiceConnector, handle_observe
from finishup.domain.events import EvidenceRecordedPayload, ResultRecordedPayload
from finishup.domain.observation import (
    ObservationCursor,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationSource,
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.workspace_effect import workspace_effect_from_annotation
from finishup.kernel.closing_review_delta import closing_review_delta
from finishup.kernel.later_material import workspace_effects
from finishup.kernel.reducers import replay as replay_ledger
from finishup.ports.ledger import FrozenCase
from finishup.protocol.canonical import JsonValue, canonical_encode
from fixture_loader import load_fixture_json
from integration.application.test_native_capture_pipeline import _pipeline


@pytest.mark.anyio
@pytest.mark.parametrize("stream_first", [False, True])
async def test_plain_bash_f1_capture_and_stream_overlap(tmp_path: Path, stream_first: bool) -> None:
    raw_session = "n6-overlap"
    (
        project,
        workspace,
        session,
        local,
        store,
        ledger,
        runtime,
        coordinator,
        _,
        connect,
    ) = await _pipeline(tmp_path, codex_session_id=raw_session, profile=None)
    fixture = cast(
        dict[str, object],
        load_fixture_json("observations/codex-post-tool-outcomes-0.157.1.case.json"),
    )
    hook = cast(dict[str, object], cast(dict[str, object], fixture["input"])["hook"])
    shape = cast(dict[str, object], hook["code_mode_exec_command_exit_0"])
    post = cast(dict[str, object], json.loads(json.dumps(shape["payload"])))
    post.update(
        session_id=raw_session,
        cwd=str(project),
        tool_name="Bash",
        tool_use_id="call-n6-overlap",
        tool_input={"command": "pytest -q"},
    )
    response = cast(dict[str, JsonValue], json.loads(cast(str, post["tool_response"])))
    response["output"] = "12 passed native-overlap-output"
    # The hook states its exit through the host-structured result object: as text the response
    # would be the command's own output, never an outcome (n7 RC1, #1105). The strict hook parser
    # refuses a fractional number in an object, so the wall time is left out.
    response.pop("wall_time_seconds", None)
    post["tool_response"] = cast(JsonValue, response)

    def run_async(factory: Callable[[], Awaitable[object]]) -> object:
        return asyncio.run(factory())

    def hook_call(kind: str) -> int:
        payload = {**post, "hook_event_name": kind}
        if kind == "PreToolUse":
            payload.pop("tool_response")
        return handle_observe(
            event_name=kind,
            stdin_bytes=canonical_encode(cast(JsonValue, payload)),
            workspace=str(project),
            _state=tmp_path / "state",
            stdout=io.BytesIO(),
            connect=cast(ServiceConnector, connect),
            run_async=run_async,
            source=ObservationSource.CODEX_HOOK,
        )

    assert await asyncio.to_thread(hook_call, "PreToolUse") == 0
    pre = next(item for item in local.list_envelopes(workspace) if item.event_kind == "PreToolUse")
    rollout = tmp_path / "rollout.jsonl"
    # Derived from OUT-001's recorded CommandExecution: only command/id/output vary.
    rollout_case = cast(dict[str, object], cast(dict[str, object], fixture["input"])["rollout"])
    lines = json.loads(json.dumps(rollout_case["lines"]))
    completed = lines[2]
    completed["payload"]["item"].update(
        id="call-n6-overlap",
        command=["/bin/bash", "-lc", "pytest -q"],
        stdout="12 passed native-overlap-output",
    )
    rollout.write_text("".join(json.dumps(line) + "\n" for line in [lines[0], completed]))
    reader = SessionStreamReader(
        session_commitment=session,
        profile=None,
        cursor=ObservationCursor(
            pre.cursor.source_generation, 0, 0, "hmac-sha256:" + "0" * 64, STREAM_MAPPING_VERSION
        ),
        key_material=local.key_material(),
    )
    stream = next(
        item for item in reader.advance(rollout).envelopes if item.event_kind == "item_completed"
    )

    async def ingest_stream() -> None:
        result = await coordinator.ingest_request(
            ObservationIngestRequest(codex_session_id=raw_session, envelope=stream)
        )
        assert result.disposition in {
            ObservationIngestDisposition.ACCEPTED,
            ObservationIngestDisposition.DUPLICATE,
        }, result.reason

    if stream_first:
        await ingest_stream()
    assert await asyncio.to_thread(hook_call, "PostToolUse") == 0
    if not stream_first:
        await ingest_stream()
    # A stream-first delivery can itself gain captured output after the hook's enrichment.
    await ingest_stream()
    before = await ledger.load_frontier()
    await ingest_stream()
    assert await ledger.load_frontier() == before
    assert local.pending_outbox_count(workspace) == 0
    assert local.quarantined_count(workspace) == 0
    assert store.list_pending_capture_tickets(runtime.task_id) == ()
    records = tuple([row async for row in ledger.load_events(runtime.session_id)])
    assert len([row for row in records if type(row.payload) is ResultRecordedPayload]) == 1
    from finishup.domain.workspace_effect import workspace_effect_from_annotation

    rows = [row.payload for row in records if type(row.payload) is EvidenceRecordedPayload]
    # PR #1080 round 6: when the stream copy is recorded first, the hook post's workspace fact
    # still reaches the call as one metadata-only annotation row; hook-first needs none.
    annotations = [
        effect
        for item in rows
        if (effect := workspace_effect_from_annotation(item.description)) is not None
    ]
    assert annotations == (["unchanged"] if stream_first else [])
    evidence = [item for item in rows if workspace_effect_from_annotation(item.description) is None]
    # Both command input (eligibility context) and output survive even in stream-first order.
    assert len(evidence) == 2
    manifests = [
        store.load_content_manifest(str(item.captured_object_id))
        for item in evidence
        if item.captured_object_id is not None
    ]
    assert {item.content_kind.value for item in manifests if item is not None} >= {
        "tool_input",
        "tool_output",
    }
    assert any(item.captured_object_id is not None for item in evidence)
    frontier = await ledger.load_frontier()
    frozen = await ledger.freeze_case(
        runtime.session_id,
        cast(str, runtime.writer_id),
        frontier.sequence,
        "req_00000000-0000-4000-8000-000000008081",
        "sha256:" + "0" * 64,
    )
    assert isinstance(frozen, FrozenCase)
    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=workspace,
        local_observation=local,
    )
    # New evidence retains its action lineage and same-phase authenticated eligibility.
    assert any(item.observed_command == "pytest -q" for item in resolved.content)
    assert all(item.manifest.content_kind.value != "tool_input" for item in resolved.content)
    from unit.application.test_review_follow_up import _build, _provider_contents, _requested, _send

    result_id = next(iter(frozen.case.projection.results))
    follow_up = plan_review_follow_up(
        frozen.case.projection,
        frozenset(map(str, frozen.case.allowed_ids)),
        (_requested("verification_output", str(result_id), availability="agent_suppliable"),),
        previous=None,
        shown_refs=frozenset(),
    )
    assert follow_up is not None
    built = _build(
        frozen.case,
        follow_up=follow_up,
        selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED),
        captured_content=resolved.content,
        captured_content_scope=resolved.scope,
        workspace_root=str(project),
    )
    assert b"native-overlap-output" in _provider_contents(_send(built))
    unbound = _build(
        frozen.case,
        follow_up=follow_up,
        selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED),
        captured_content=tuple(
            replace(item, observed_command_identity=None) for item in resolved.content
        ),
        captured_content_scope=resolved.scope,
        workspace_root=str(project),
    )
    assert b"native-overlap-output" not in _provider_contents(_send(unbound))


@pytest.mark.anyio
@pytest.mark.parametrize("conflict", [False, True])
async def test_image_enrichment_keeps_core_conflicts_fail_closed(
    tmp_path: Path, conflict: bool
) -> None:
    from finishup.domain.values import JsonObject
    from unit.application.test_observation_coordinator import (
        _envelope,
        _reattach_fixture,
        _schema_rows,
    )

    cell = _reattach_fixture(tmp_path, "image-enrichment")
    hook = _envelope(
        session=cell.session,
        kind="PostToolUse",
        identity="hook:image-core",
        corr="call-image",
        tool="view_image",
        exit_status=0,
    )
    first = await cell.ingest(hook)
    assert first.disposition is ObservationIngestDisposition.ACCEPTED
    enriched = replace(
        hook,
        source_identity="stream:image-enriched",
        source=ObservationSource.CODEX_SESSION_STREAM,
        structural_payload=JsonObject(
            {
                **hook.structural_payload,
                "observed_images": [
                    {
                        "content_digest": "sha256:" + "a" * 64,
                        "byte_count": 128,
                        "media_type": "image/png",
                    }
                ],
            }
        ),
    )
    if conflict:
        # A second hook's explicit, contradictory outcome has no stream correction authority.
        enriched = replace(
            enriched,
            source=ObservationSource.CODEX_HOOK,
            structural_payload=JsonObject({**enriched.structural_payload, "exit_status": 1}),
        )
    result = await cell.ingest(enriched)
    if conflict:
        assert result.disposition is ObservationIngestDisposition.REJECTED
        assert result.reason == "ledger_rejected"
        assert _schema_rows(cell, "evidence_recorded") == []
    else:
        assert result.disposition is ObservationIngestDisposition.ACCEPTED, result.reason
        assert len(_schema_rows(cell, "evidence_recorded")) == 1
        before = cell.operation_count()
        again = await cell.ingest(enriched)
        assert again.disposition is ObservationIngestDisposition.DUPLICATE
        assert cell.operation_count() == before
        other_source = replace(enriched, source_identity="stream:second-image-source")
        other = await cell.ingest(other_source)
        assert other.disposition is ObservationIngestDisposition.ACCEPTED, other.reason
        assert len(_schema_rows(cell, "evidence_recorded")) == 2
        count = cell.operation_count()
        assert (
            await cell.ingest(other_source)
        ).disposition is ObservationIngestDisposition.DUPLICATE
        assert cell.operation_count() == count
    assert len(_schema_rows(cell, "result_recorded")) == 1


@pytest.mark.anyio
@pytest.mark.parametrize("races", [1, 2])
async def test_partial_overlap_racing_append_is_reconciled_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, races: int
) -> None:
    from finishup.domain.values import JsonObject
    from finishup.ports.ledger import AppendCommand, AppendResult
    from unit.application.test_observation_coordinator import (
        _envelope,
        _reattach_fixture,
        _schema_rows,
    )

    cell = _reattach_fixture(tmp_path, "racing-image-enrichment")
    hook = _envelope(
        session=cell.session,
        kind="PostToolUse",
        identity="hook:race-core",
        corr="call-race",
        tool="view_image",
        exit_status=0,
    )
    assert (await cell.ingest(hook)).disposition is ObservationIngestDisposition.ACCEPTED
    enriched = replace(
        hook,
        source_identity="stream:race-enriched",
        source=ObservationSource.CODEX_SESSION_STREAM,
        structural_payload=JsonObject(
            {
                **hook.structural_payload,
                "observed_images": [
                    {
                        "content_digest": "sha256:" + digest * 64,
                        "byte_count": 128,
                        "media_type": "image/png",
                    }
                    for digest in ("a", "b", "c")[: races + 1]
                ],
            }
        ),
    )
    append = cell.ledger.append_batch
    raced = 0

    async def racing_append(command: AppendCommand) -> AppendResult:
        nonlocal raced
        if raced < races and len(command.entries) > 1:
            raced += 1
            await append(
                replace(
                    command,
                    entries=command.entries[:1],
                    operation_id=f"req_00000000-0000-4000-8000-00000000808{raced}",
                    request_digest="sha256:" + str(raced) * 64,
                )
            )
        return await append(command)

    monkeypatch.setattr(cell.ledger, "append_batch", racing_append)
    result = await cell.ingest(enriched)
    assert raced == races
    if races == 2:
        assert result.disposition is ObservationIngestDisposition.REJECTED
        assert result.reason == "service_unavailable"
        assert cell.local.quarantined_count(cell.workspace) == 0
        result = await cell.ingest(enriched)
        assert result.disposition in {
            ObservationIngestDisposition.ACCEPTED,
            ObservationIngestDisposition.DUPLICATE,
        }, result.reason
    else:
        assert result.disposition is ObservationIngestDisposition.ACCEPTED, result.reason
    assert len(_schema_rows(cell, "evidence_recorded")) == races + 1
    count = cell.operation_count()
    assert (await cell.ingest(enriched)).disposition is ObservationIngestDisposition.DUPLICATE
    assert cell.operation_count() == count


@pytest.mark.anyio
async def test_replayed_call_cannot_replace_its_keyed_command(tmp_path: Path) -> None:
    from finishup.domain.values import JsonObject
    from unit.application.test_observation_coordinator import (
        _envelope,
        _reattach_fixture,
        _schema_rows,
    )

    cell = _reattach_fixture(tmp_path, "command-conflict")
    pre = _envelope(session=cell.session, kind="PreToolUse", identity="hook:command-pre")
    pre = replace(
        pre,
        structural_payload=JsonObject(
            {**pre.structural_payload, "command_commitment": "hmac-sha256:" + "a" * 64}
        ),
    )
    assert (await cell.ingest(pre)).disposition is ObservationIngestDisposition.ACCEPTED
    post = replace(
        pre,
        event_kind="PostToolUse",
        source_identity="hook:command-post",
        structural_payload=JsonObject(
            {
                **pre.structural_payload,
                "command_commitment": "hmac-sha256:" + "b" * 64,
                "exit_status": 0,
            }
        ),
    )
    result = await cell.ingest(post)
    assert result.disposition is ObservationIngestDisposition.REJECTED
    assert result.reason == "ledger_rejected"
    assert _schema_rows(cell, "result_recorded") == []


@pytest.mark.anyio
@pytest.mark.parametrize("preexisting_b", [False, True])
async def test_evidence_only_collision_cannot_create_another_calls_core(
    tmp_path: Path, preexisting_b: bool
) -> None:
    """R3 finding 1: same source/image, different call; B's own pre-action is insufficient."""

    from finishup.domain.values import JsonObject
    from unit.application.test_observation_coordinator import _envelope, _reattach_fixture

    cell = _reattach_fixture(tmp_path, "r4-evidence-lineage")
    first = _envelope(
        session=cell.session,
        kind="PostToolUse",
        identity="source:fixed",
        corr="call-A",
        tool="view_image",
        exit_status=0,
    )
    first = replace(
        first,
        structural_payload=JsonObject(
            {
                **first.structural_payload,
                "observed_images": [
                    {
                        "content_digest": "sha256:" + "a" * 64,
                        "byte_count": 128,
                        "media_type": "image/png",
                    }
                ],
            }
        ),
    )
    assert (await cell.ingest(first)).disposition is ObservationIngestDisposition.ACCEPTED
    if preexisting_b:
        pre = _envelope(
            session=cell.session,
            kind="PreToolUse",
            identity="source:pre-B",
            corr="call-B",
            tool="view_image",
        )
        assert (await cell.ingest(pre)).disposition is ObservationIngestDisposition.ACCEPTED
    before = cell.record_count()
    second = replace(
        first,
        structural_payload=JsonObject(
            {**first.structural_payload, "tool_call_id": "call-B", "correlation_id": "call-B"}
        ),
    )
    refused = await cell.ingest(second)
    assert refused.disposition is ObservationIngestDisposition.REJECTED
    assert refused.reason == "ledger_rejected"
    assert cell.record_count() == before
    await cell.ingest(second)
    assert cell.record_count() == before


@pytest.mark.anyio
async def test_same_call_image_overlap_can_append_another_image(tmp_path: Path) -> None:
    from finishup.domain.values import JsonObject
    from unit.application.test_observation_coordinator import (
        _envelope,
        _reattach_fixture,
        _schema_rows,
    )

    cell = _reattach_fixture(tmp_path, "r4-same-call")
    first = _envelope(
        session=cell.session,
        kind="PostToolUse",
        identity="source:fixed",
        corr="call-A",
        tool="view_image",
        exit_status=0,
    )
    image = {"content_digest": "sha256:" + "a" * 64, "byte_count": 128, "media_type": "image/png"}
    first = replace(
        first,
        structural_payload=JsonObject({**first.structural_payload, "observed_images": [image]}),
    )
    assert (await cell.ingest(first)).disposition is ObservationIngestDisposition.ACCEPTED
    enriched = replace(
        first,
        source=ObservationSource.CODEX_SESSION_STREAM,
        structural_payload=JsonObject(
            {
                **first.structural_payload,
                "observed_images": [image, {**image, "content_digest": "sha256:" + "b" * 64}],
            }
        ),
    )
    result = await cell.ingest(enriched)
    assert result.disposition is ObservationIngestDisposition.ACCEPTED, result.reason
    assert len(_schema_rows(cell, "action_recorded")) == 1
    assert len(_schema_rows(cell, "result_recorded")) == 1
    assert len(_schema_rows(cell, "evidence_recorded")) == 2


@pytest.mark.anyio
@pytest.mark.parametrize("prior_exit", [None, 0, 1])
async def test_a_hook_outcome_agrees_with_a_stream_copy_that_stated_none(
    tmp_path: Path, prior_exit: int | None
) -> None:
    """A committed copy without an outcome takes a later copy's explicit one (PR #1080 round 7).

    The stream copy stated no outcome (``prior_exit=None``): a content-bearing hook copy that
    states one agrees and its new evidence is recorded, as on 0.3. A stream copy that stated a
    different explicit outcome still makes the hook copy's contradiction a refusal.
    """

    from finishup.domain.values import JsonObject
    from unit.application.test_observation_coordinator import (
        _envelope,
        _reattach_fixture,
        _schema_rows,
    )

    cell = _reattach_fixture(tmp_path, f"unknown-prior-{prior_exit}")
    stream = _envelope(
        session=cell.session,
        kind="function_call_output",
        identity="stream:unknown-prior",
        corr="call-unknown",
        exit_status=prior_exit,
        source=ObservationSource.CODEX_SESSION_STREAM,
    )
    assert (await cell.ingest(stream)).disposition is ObservationIngestDisposition.ACCEPTED
    prior = _schema_rows(cell, "result_recorded")[0].payload
    assert type(prior) is ResultRecordedPayload
    assert (prior.outcome.value == "unknown") is (prior_exit is None)
    image = {"content_digest": "sha256:" + "c" * 64, "byte_count": 128, "media_type": "image/png"}
    hook = _envelope(
        session=cell.session,
        kind="PostToolUse",
        identity="hook:unknown-prior",
        corr="call-unknown",
        exit_status=0,
    )
    hook = replace(
        hook,
        structural_payload=JsonObject({**hook.structural_payload, "observed_images": [image]}),
    )
    result = await cell.ingest(hook)
    if prior_exit == 1:
        assert result.disposition is ObservationIngestDisposition.REJECTED
        assert result.reason == "ledger_rejected"
        assert _schema_rows(cell, "evidence_recorded") == []
    else:
        assert result.disposition is ObservationIngestDisposition.ACCEPTED, result.reason
        assert len(_schema_rows(cell, "evidence_recorded")) == 1
    assert len(_schema_rows(cell, "result_recorded")) == 1


@pytest.mark.anyio
async def test_a_captured_hook_post_after_its_stream_copy_keeps_evidence_and_fact(
    replay: CodexReplay,
) -> None:
    """Stream ``function_call_output`` first, then a content-bearing Codex hook post (round 7).

    The stream copy states no outcome; the hook copy states one and carries captured output and
    the workspace fact. Before the fix the overlap check refused it and the delivery was
    quarantined, losing both; now they are recorded and the unchanged command stays quiet. The
    next call (``ls``) completes hook-after-stream as well.
    """

    timestamp = "2026-10-09T08:00:01.000Z"

    def call_rows(call: str, command: str) -> tuple[dict[str, object], dict[str, object]]:
        return (
            rollout_row(
                "response_item",
                {
                    "arguments": json.dumps({"cmd": command}),
                    "call_id": call,
                    "id": f"fc_{call}",
                    "name": "exec_command",
                    "type": "function_call",
                },
                timestamp,
            ),
            rollout_row(
                "response_item",
                {
                    "call_id": call,
                    "id": f"fco_{call}",
                    "output": "Exit code: 0\nOutput:\npublic synthetic",
                    "type": "function_call_output",
                },
                timestamp,
            ),
        )

    def pre(call: str, command: str) -> None:
        replay.hook(
            "PreToolUse", tool_name="Bash", tool_use_id=call, tool_input={"command": command}
        )

    def post(call: str, command: str) -> None:
        replay.hook(
            "PostToolUse",
            tool_name="Bash",
            tool_use_id=call,
            tool_input={"command": command},
            tool_response=json.dumps(
                {
                    "chunk_id": call[-4:],
                    "exit_code": 0,
                    "original_token_count": 1,
                    "output": "x",
                    "wall_time_seconds": 0.1,
                }
            ),
        )

    session_start(replay, cli_version="0.159.3")
    pre("call_a1", "date -u")
    replay.append(*call_rows("call_a1", "date -u"))
    # The next call's hook makes the reader deliver the first call's stream copy first.
    pre("call_b1", "ls")
    await sweep_all(replay, capture_hook_output=True)
    stream_results = replay.rows("result_recorded")
    assert len(stream_results) == 1
    stream_result = stream_results[0].payload
    assert type(stream_result) is ResultRecordedPayload
    assert stream_result.outcome.value == "unknown"
    captured_before = [
        row
        for row in replay.rows("evidence_recorded")
        if type(row.payload) is EvidenceRecordedPayload
        and row.payload.captured_object_id is not None
    ]
    post("call_a1", "date -u")
    replay.append(*call_rows("call_b1", "ls"))
    post("call_b1", "ls")
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    recorder = await sweep_all(replay, capture_hook_output=True)

    assert recorder.refused == []
    records = tuple(replay.ledger._state.records)
    evidence = [row.payload for row in records if type(row.payload) is EvidenceRecordedPayload]
    captured = [item for item in evidence if item.captured_object_id is not None]
    assert len(captured) > len(captured_before)
    annotations = [
        effect
        for item in evidence
        if (effect := workspace_effect_from_annotation(item.description)) is not None
    ]
    assert annotations == ["unchanged"]
    state = replay_ledger(records)
    effects = workspace_effects(records, state)
    assert effects.quiet
    assert not any(closing_review_delta(row, state, effects=effects) for row in records)
