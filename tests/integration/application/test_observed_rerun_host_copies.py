"""A Codex shell re-run supplies the reviewer's request from either host copy (issue #1107, W6).

Host-shaped input only: the Codex ``PostToolUse`` payload comes from the recorded
``codex-post-tool-outcomes`` fixture through the real hook mapping (``handle_observe``), and the
session-stream copy from the same fixture's recorded rollout through ``SessionStreamReader`` and
the service's observation coordinator, in both commit orders. On Codex 0.159 the run's output
arrives through whichever copy commits first; when the stream copy wins, the hook's captured
output is linked late to the run's action event and no result cites it (ADR-006 amendment). The
hook copy states no exit (#1105): when it commits first its result reads ``unknown`` and the
stream copy appends the corrected result to the same action.

The agent's first ``pytest -q`` run is the target of a pending ``verification_output`` request;
the agent then re-runs the same command. The real ``supplied_since`` names the re-run's observed
result and its captured tool output (never the captured command input), the real packet builder
carries that output, and a repeat of the request is dropped as already supplied only when the sent
packet held it.
"""

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

from builders.review_manifests import follow_up_round, run_sources
from finishup.adapters.integrations.codex_session_stream import SessionStreamReader
from finishup.adapters.integrations.observation_local import STREAM_MAPPING_VERSION
from finishup.application.missing_for_assessment import (
    review_missing_for_assessment,
    supplied_since,
)
from finishup.application.semantic_case import (
    assemble_filtered_review_packet,
    bounded_case_envelope,
    build_semantic_case,
    semantic_case_packet_view,
    sent_excerpt_content_refs,
    sent_excerpt_parts,
)
from finishup.application.semantic_content import resolve_captured_semantic_content
from finishup.cli.observe_hooks import ServiceConnector, handle_observe
from finishup.domain.events import (
    EvidenceRecordedPayload,
    MissingForAssessmentItem,
    ResultOutcome,
    ResultRecordedPayload,
    is_observation_authored,
)
from finishup.domain.observation import (
    ObservationCursor,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationSource,
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.values import event_id
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.kernel.projections import PendingMissingForAssessment
from finishup.ports.ledger import FrozenCase
from finishup.ports.semantic import MissingForAssessment, SemanticCase, SemanticJudgment
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from fixture_loader import load_fixture_json
from integration.application.test_native_capture_pipeline import _pipeline

pytestmark = pytest.mark.anyio

_SESSION = "w6-rerun-copies"
_COMMAND = "pytest -q"
_REQUEST = event_id("evt_60000000-0000-4000-8000-000000000001")


def _send(case: SemanticCase) -> bytes:
    """The exact packet a provider receives when privacy approves every item."""

    envelope = strict_json_parse(bounded_case_envelope(case))
    assert isinstance(envelope, dict)
    content = {item.item_id: item.content for item in case.items}
    return assemble_filtered_review_packet(
        envelope, content_by_id=content, included_item_ids=frozenset(content)
    )


def _manifest(prepared: bytes) -> dict[str, JsonValue]:
    document = strict_json_parse(prepared)
    assert isinstance(document, dict)
    packet = document["review_packet"]
    assert isinstance(packet, dict)
    manifest = packet["provider_input_manifest"]
    assert isinstance(manifest, dict)
    return manifest


def _contents(prepared: bytes) -> bytes:
    document = strict_json_parse(prepared)
    assert isinstance(document, dict)
    rows = document["items"]
    assert isinstance(rows, list)
    parts: list[bytes] = []
    for row in rows:
        content = row.get("content") if isinstance(row, dict) else None
        if isinstance(content, str):
            parts.append(content.encode())
    return b"\n".join(parts)


@pytest.mark.parametrize("stream_first", [False, True])
async def test_a_codex_rerun_supplies_the_request_from_either_host_copy(
    tmp_path: Path, stream_first: bool
) -> None:
    (
        project,
        workspace,
        session,
        local,
        _store,
        ledger,
        runtime,
        coordinator,
        _,
        connect,
    ) = await _pipeline(tmp_path, codex_session_id=_SESSION, profile=None)
    fixture = cast(
        dict[str, object],
        load_fixture_json("observations/codex-post-tool-outcomes-0.157.1.case.json"),
    )
    recorded = cast(dict[str, object], fixture["input"])
    hook = cast(dict[str, object], recorded["hook"])
    shape = cast(dict[str, object], hook["code_mode_exec_command_exit_0"])

    def post_for(call: str, output: str) -> dict[str, object]:
        # Only the session, workspace, call id, command and output vary from the recorded post.
        post = cast(dict[str, object], json.loads(json.dumps(shape["payload"])))
        post.update(
            session_id=_SESSION,
            cwd=str(project),
            tool_name="Bash",
            tool_use_id=call,
            tool_input={"command": _COMMAND},
        )
        response = json.loads(cast(str, post["tool_response"]))
        response["output"] = output
        post["tool_response"] = json.dumps(response)
        return post

    def run_async(factory: Callable[[], Awaitable[object]]) -> object:
        async def await_result() -> object:
            return await factory()

        return asyncio.run(await_result())

    def hook_call(post: dict[str, object], kind: str) -> int:
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

    # The agent's first run, the target of the reviewer's request.
    first = post_for("call-w6-first", "1 failed w6-first-run-output")
    assert await asyncio.to_thread(hook_call, first, "PreToolUse") == 0
    assert await asyncio.to_thread(hook_call, first, "PostToolUse") == 0
    requested_at = (await ledger.load_frontier()).sequence
    target = next(
        str(row.payload.result_id)
        for row in [item async for item in ledger.load_events(runtime.session_id)]
        if type(row.payload) is ResultRecordedPayload
    )

    # The re-run of the same command, committed by the hook and Codex's session-stream copy.
    rerun = post_for("call-w6-rerun", "3 passed w6-rerun-output")
    assert await asyncio.to_thread(hook_call, rerun, "PreToolUse") == 0
    pre = next(
        item
        for item in local.list_envelopes(workspace)
        if item.event_kind == "PreToolUse"
        and item.structural_payload.get("tool_call_id") == "call-w6-rerun"
    )
    rollout_case = cast(dict[str, object], recorded["rollout"])
    lines = json.loads(json.dumps(rollout_case["lines"]))
    completed = lines[2]
    completed["payload"]["item"].update(
        id="call-w6-rerun",
        command=["/bin/bash", "-lc", _COMMAND],
        stdout="3 passed w6-rerun-output",
    )
    rollout = tmp_path / "rollout.jsonl"
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
    assert stream.source is ObservationSource.CODEX_SESSION_STREAM

    async def ingest_stream() -> None:
        result = await coordinator.ingest_request(
            ObservationIngestRequest(codex_session_id=_SESSION, envelope=stream)
        )
        assert result.disposition in {
            ObservationIngestDisposition.ACCEPTED,
            ObservationIngestDisposition.DUPLICATE,
        }, result.reason

    if stream_first:
        await ingest_stream()
    assert await asyncio.to_thread(hook_call, rerun, "PostToolUse") == 0
    if not stream_first:
        await ingest_stream()

    frontier = await ledger.load_frontier()
    frozen = await ledger.freeze_case(
        runtime.session_id,
        cast(str, runtime.writer_id),
        frontier.sequence,
        "req_60000000-0000-4000-8000-000000000002",
        "sha256:" + "0" * 64,
    )
    assert isinstance(frozen, FrozenCase)
    request = MissingForAssessmentItem("verification_output", (target,), "agent_suppliable")
    pending = PendingMissingForAssessment(_REQUEST, requested_at, (request,))
    # The frozen case names the observation-authored events after the pending request, exactly as
    # the kernel derives them when the ledger holds that request.
    records = [item async for item in ledger.load_events(runtime.session_id)]
    case: DeterministicCase = replace(
        frozen.case,
        projection=replace(frozen.case.projection, pending_missing_for_assessment=pending),
        observation_event_ids=frozenset(
            record.event_id
            for record in records
            if record.ledger.ingestion_sequence > requested_at and is_observation_authored(record)
        ),
    )
    projection = case.projection
    observed = frozenset(str(item) for item in case.observation_event_ids)
    allowed = frozenset(str(ref) for ref in case.allowed_ids)
    rerun_results = [
        (str(ref), row)
        for ref, row in projection.results.items()
        if row.source_frontier > requested_at
    ]
    # #1105: a Codex hook post is a completion fact only, so with the hook first its result reads
    # ``unknown`` and the joined session-stream item appends the corrected result to the same
    # action. Stream first, the stream's result is the run's only one.
    assert len(rerun_results) == (1 if stream_first else 2)
    payloads = [row.payload for _ref, row in rerun_results]
    assert all(payload is not None for payload in payloads)
    assert len({str(payload.action_id) for payload in payloads if payload is not None}) == 1
    assert [(payload.outcome, payload.exit_status) for payload in payloads if payload is not None][
        -1
    ] == (ResultOutcome.SUCCESS, 0)
    # Stream first, the observed result cites none of the hook's capture: it is linked late to
    # the run's action event instead. Hook first, the hook's result cites it.
    cited = {
        str(ref) for payload in payloads if payload is not None for ref in payload.evidence_refs
    }
    captured = {
        str(ref): row.payload
        for ref, row in projection.evidence.items()
        if row.source_frontier > requested_at
        and row.payload is not None
        and row.payload.captured_object_id is not None
    }

    def is_output(payload: EvidenceRecordedPayload) -> bool:
        return (payload.description or "").startswith("Observation-captured tool_output ")

    output = {ref for ref, payload in captured.items() if is_output(payload)}
    command_input = set(captured) - output
    assert output and command_input
    assert not (output & cited) if stream_first else output <= cited

    (supplied,) = supplied_since(projection, pending, allowed, observed)
    # The re-run's results and its captured output answer the request: hook first, the stream's
    # corrected result is the same run, so it carries the output the hook's result cites
    # (#1105 with #1107). The captured command input is not output and never listed.
    assert {ref for ref, _row in rerun_results} <= set(supplied)
    assert output <= set(supplied)
    assert not command_input & set(supplied)

    # The real packet carries the re-run's captured output when the owner's selection sends
    # repository excerpts, and the repeat is then already supplied.
    resolved = await resolve_captured_semantic_content(
        runtime=runtime, frozen=frozen, workspace_commitment=workspace, local_observation=local
    )
    follow_up = follow_up_round(
        ("verification_output", (target,), run_sources(projection, target, allowed) | output)
    )

    def review(profile: ReviewContextProfile) -> tuple[bytes, list[str], frozenset[str]]:
        built = build_semantic_case(
            case_id="cas_60000000-0000-4000-8000-000000000003",
            frozen_case=case,
            dependency_digest="sha256:" + "b" * 64,
            findings=(),
            review_context_profile=profile,
            review_selection=ReviewSelectionPolicy.for_profile(profile),
            policy_id="pvy_60000000-0000-4000-8000-000000000004",
            policy_version="1",
            follow_up=follow_up,
            captured_content=resolved.content,
            captured_content_scope=resolved.scope,
            workspace_root=str(project),
        )
        sent = _send(built)
        # The stream's outcome correction is the same run, never a newer run that left no output
        # and supersedes the run's own capture (#1105 with #1045).
        assert not {ref for item in built.items for ref in item.superseded_by} & {
            ref for ref, _row in rerun_results
        }
        manifest = _manifest(sent)
        verdict = review_missing_for_assessment(
            case,
            (),
            SemanticJudgment(
                "insufficient_packet",
                (),
                missing_for_assessment=(
                    MissingForAssessment("verification_output", (target,), "still absent"),
                ),
            ),
            unsuppliable_kinds=frozenset(),
            citable_refs=semantic_case_packet_view(built).citable_refs,
            workspace_root=str(project),
            excerpt_refs=sent_excerpt_content_refs(built, manifest),
            excerpt_parts=sent_excerpt_parts(built, manifest),
        )
        return _contents(sent), [item.kind for item in verdict.items], verdict.gaps

    contents, kinds, gaps = review(ReviewContextProfile.ASSISTED)
    assert b"w6-rerun-output" in contents
    # Owner decision B (#1118 unit 4): supplied and disclosed; the reviewer's repeat stays.
    assert kinds == ["verification_output"]
    assert "semantic_missing_already_supplied" in gaps

    # A selection that sends no repository excerpt never carries it: the item stays the agent's.
    contents, kinds, gaps = review(ReviewContextProfile.STRUCTURAL)
    assert b"w6-rerun-output" not in contents
    assert kinds == ["verification_output"]
    assert "semantic_missing_already_supplied" not in gaps
