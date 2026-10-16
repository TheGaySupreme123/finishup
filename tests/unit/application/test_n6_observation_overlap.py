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
    response = json.loads(cast(str, post["tool_response"]))
    response["output"] = "12 passed native-overlap-output"
    post["tool_response"] = json.dumps(response)

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
    evidence = [row.payload for row in records if type(row.payload) is EvidenceRecordedPayload]
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
