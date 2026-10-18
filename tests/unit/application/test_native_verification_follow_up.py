"""Native post-tool capture -> materialization -> resolver -> provider packet (F1)."""

# pyright: reportPrivateUsage=false
from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from builders.policy_cases import evidence_record, make_case, record
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.missing_for_assessment import plan_review_follow_up
from finishup.application.observation_materialize import materialize_observation_envelope
from finishup.application.semantic_case import CapturedSemanticContent
from finishup.application.semantic_content import (
    CapturedContentResolution,
    resolve_captured_semantic_content,
)
from finishup.cli.observe_hooks import _visible_content_chunks, map_hook_payload_to_envelope
from finishup.domain.events import (
    ActionRecordedPayload,
    EvidenceRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from finishup.domain.observation import ObservationContentKind, ObservationContentManifest
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.values import (
    ActionId,
    EvidenceId,
    JsonObject,
    ResultId,
    object_id,
    result_id,
    timestamp_from_string,
)
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.kernel.projections import EvidenceProjectionRecord, ProjectionRecord
from finishup.ports.ledger import FrozenCase
from finishup.ports.objects import ObjectRef, ObjectStorePort
from finishup.ports.observation import TaskObservationPort
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.coverage import PublicationChannel, coverage_for_channel
from fixture_loader import load_fixture_json
from unit.application.test_review_follow_up import (
    _OBSERVED_MARKER,
    _build,
    _provider_contents,
    _requested,
    _send,
)
from unit.application.test_semantic_content import (
    _SESSION_COMMITMENT,
    _TASK,
    _WORKSPACE,
    _fixture,
    _Objects,
    _Observation,
)


async def _native_capture(
    tmp_path: Path, command: str, output: bytes
) -> tuple[
    DeterministicCase,
    CapturedContentResolution,
    dict[ActionId, ProjectionRecord[ActionRecordedPayload]],
    dict[ResultId, ProjectionRecord[ResultRecordedPayload]],
]:
    """A recorded Codex post-tool payload with ``command`` and ``output``, materialized, frozen
    and resolved to its captured semantic content."""

    frozen, runtime, base_objects, _observation, _envelope = _fixture()
    fixture = load_fixture_json("observations/codex-post-tool-outcomes-0.157.1.case.json")
    hook = cast(dict[str, object], cast(dict[str, object], fixture)["input"])["hook"]
    shape = cast(dict[str, object], hook)["code_mode_exec_command_exit_0"]
    raw_payload = cast(dict[str, object], shape)["payload"]
    # Substitute only task content in the recorded-rollout-derived native shape.
    payload_value = cast(dict[str, object], json.loads(json.dumps(raw_payload)))
    payload_value["tool_input"] = {"command": command}
    response = json.loads(cast(str, payload_value["tool_response"]))
    response["output"] = output.decode()
    payload_value["tool_response"] = json.dumps(response)
    payload = JsonObject(payload_value)  # pyright: ignore[reportArgumentType]
    assert "exit_status" not in payload
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        payload,
        session_commitment=_SESSION_COMMITMENT,
        event_ordinal=1,
        key_material=b"k" * 32,
    )
    chunks, truncated = _visible_content_chunks(
        "PostToolUse", payload, envelope=envelope, workspace_locator="/app"
    )
    assert not truncated
    assert {chunk.content_kind for chunk in chunks} == {
        ObservationContentKind.TOOL_INPUT,
        ObservationContentKind.TOOL_OUTPUT,
    }
    refs: dict[str, ObjectRef] = {}
    wrappers: dict[str, bytes] = {}
    manifests: dict[str, ObservationContentManifest] = {}
    for index, chunk in enumerate(chunks):
        oid = object_id(f"obj_00000000-0000-4000-8000-{index + 100:012x}")
        wrapper = canonical_encode(
            JsonObject(
                {
                    "format": "yoetz.observation-content/1",
                    "content_kind": chunk.content_kind.value,
                    "correlation_identity": chunk.correlation_identity,
                    "source_commitment": chunk.source_commitment,
                    "media_type": chunk.media_type,
                    "part_index": chunk.part_index,
                    "part_count": chunk.part_count,
                    "redacted": chunk.redacted,
                    "content_b64": base64.b64encode(chunk.content).decode(),
                }
            )
        )
        ref = replace(
            base_objects.ref,
            object_id=oid,
            plaintext_size=len(wrapper),
            envelope_digest="sha256:" + f"{index + 100:064x}",
        )
        refs[oid], wrappers[oid] = ref, wrapper
        manifests[oid] = ObservationContentManifest(
            object_id=oid,
            envelope_digest=ref.envelope_digest,
            content_kind=chunk.content_kind,
            part_index=chunk.part_index,
            part_count=chunk.part_count,
            redacted=chunk.redacted,
            content_digest="sha256:" + hashlib.sha256(chunk.content).hexdigest(),
            content_bytes=len(chunk.content),
            correlation_identity=chunk.correlation_identity,
            source_commitment=chunk.source_commitment,
        )
    envelope = replace(envelope, content_object_refs=tuple(sorted(refs)))
    batch = materialize_observation_envelope(
        envelope, task_id=_TASK, captured_content=tuple(manifests.values())
    )
    ledger_bytes = b"\n".join(item.payload_bytes for item in batch.drafts)
    assert command.encode() not in ledger_bytes
    assert b"native-output" not in ledger_bytes
    assert b'"tool_input"' not in ledger_bytes
    actions: dict[ActionId, ProjectionRecord[ActionRecordedPayload]] = {}
    results: dict[ResultId, ProjectionRecord[ResultRecordedPayload]] = {}
    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {}
    for index, item in enumerate(batch.drafts, 1):
        value = item.draft.payload
        if isinstance(value, ActionRecordedPayload):
            assert value.command is not None and value.command.startswith("omitted:hmac-sha256:")
            actions[value.action_id] = record(value, index)
        elif isinstance(value, ResultRecordedPayload):
            results[value.result_id] = record(value, index)
        elif isinstance(value, EvidenceRecordedPayload):
            evidence[value.evidence_id] = replace(
                evidence_record(value, index), source_event_id=item.draft.event_id
            )
    case = make_case(
        actions=actions,
        results=results,
        evidence=evidence,
        extra_refs=(*actions, *results, *evidence),
    )
    first = next(iter(refs))
    observation = _Observation(envelope, manifests[first], profiles=(), manifests=manifests)
    objects = _Objects(refs[first], wrappers[first], refs=refs, wrappers=wrappers)
    runtime = replace(
        runtime,
        observation=cast(TaskObservationPort, observation),
        objects=cast(ObjectStorePort, objects),
    )
    local = LocalObservationStore(_state=tmp_path / "local")
    local.grant_consent(_WORKSPACE, timestamp_from_string("2026-07-01T00:00:00.000Z"))
    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=FrozenCase(case, frozen.lease),
        workspace_commitment=_WORKSPACE,
        local_observation=local,
    )
    return case, resolved, actions, results


@pytest.mark.anyio
@pytest.mark.parametrize(
    "profile",
    (ReviewContextProfile.ASSISTED, ReviewContextProfile.EXPANDED, ReviewContextProfile.STRUCTURAL),
)
@pytest.mark.parametrize(
    "command,output,expected",
    (
        ("pytest -q", b"12 passed native-output", True),
        ("pytest -q; printenv", b"native-output", False),
        ("pytest tests/id_rsa", b"native-output", False),
        ("pytest ../outside.py", b"native-output", False),
        ("pytest -q", b"native-output\n-----END OPENSSH PRIVATE KEY-----", False),
        ("pytest -q", b"native-output\npassword=hunter2", False),
        ("pytest -q", b"native-output\n-----BEGIN OPENSSH PRIVATE KEY-----", False),
    ),
)
async def test_native_capture_follow_up(
    tmp_path: Path, profile: ReviewContextProfile, command: str, output: bytes, expected: bool
) -> None:
    case, resolved, actions, results = await _native_capture(tmp_path, command, output)
    assert len(resolved.content) == 1  # Input is eligibility context only.
    if expected:
        assert resolved.content[0].observed_command == command
    follow_up = plan_review_follow_up(
        case.projection,
        frozenset(str(ref) for ref in case.allowed_ids),
        (
            _requested(
                "verification_output", str(next(iter(results))), availability="agent_suppliable"
            ),
        ),
        previous=None,
        shown_refs=frozenset(),
    )
    assert follow_up is not None
    built = _build(
        case,
        follow_up=follow_up,
        selection=ReviewSelectionPolicy.for_profile(profile),
        captured_content=resolved.content,
        captured_content_scope=resolved.scope,
        workspace_root="/app",
    )
    prepared = _provider_contents(_send(built))
    included = expected and profile is not ReviewContextProfile.STRUCTURAL
    assert (b"native-output" in prepared) is included
    assert (_OBSERVED_MARKER.encode() in prepared) is included
    # An agent cannot replace the keyed observed identity with plaintext to authorize output.
    plaintext_actions = {
        ref: record(replace(row.payload, command=command), row.source_frontier)
        for ref, row in actions.items()
        if row.payload is not None
    }
    plaintext = replace(case, projection=replace(case.projection, actions=plaintext_actions))
    forged = _build(
        plaintext,
        follow_up=follow_up,
        selection=ReviewSelectionPolicy.for_profile(profile),
        captured_content=tuple(
            replace(item, observed_command=None, observed_command_identity=None)
            for item in resolved.content
        ),
        captured_content_scope=resolved.scope,
        workspace_root="/app",
    )
    assert _OBSERVED_MARKER.encode() not in _provider_contents(_send(forged))
    assert b"native-output" not in _provider_contents(_send(forged))
    denied = replace(
        ReviewSelectionPolicy.for_profile(profile),
        excerpt_kinds=tuple(
            kind
            for kind in ReviewSelectionPolicy.for_profile(profile).excerpt_kinds
            if kind != "diff"
        ),
    )
    withheld = _build(
        case,
        follow_up=follow_up,
        selection=denied,
        captured_content=resolved.content,
        captured_content_scope=resolved.scope,
        workspace_root="/app",
    )
    assert b"native-output" not in _provider_contents(_send(withheld))
    for identity in (None, "omitted:hmac-sha256:" + "0" * 64):
        mismatched = tuple(
            replace(item, observed_command_identity=identity) for item in resolved.content
        )
        blocked = _build(
            case,
            follow_up=follow_up,
            selection=ReviewSelectionPolicy.for_profile(profile),
            captured_content=mismatched,
            captured_content_scope=resolved.scope,
            workspace_root="/app",
        )
        assert b"native-output" not in _provider_contents(_send(blocked))


@pytest.mark.anyio
async def test_the_first_packet_labels_a_native_capture_with_its_host_reported_run(
    tmp_path: Path,
) -> None:
    """n7 RC6c (#1108): a hook-captured tool output reached the first packet unlabelled, so it
    read like the agent's own account and the reviewer abstained on it. It now names its
    provenance, and names the run's outcome and exit status only when the host recorded that run
    of that command: never from a record the host did not observe or a plaintext command."""

    case, resolved, actions, results = await _native_capture(
        tmp_path, "pytest -q", b"12 passed native-output"
    )
    (action_ref,) = actions
    (result,) = (row.payload for row in results.values())
    assert result is not None
    hooked = replace(
        case,
        coverage_by_ref={
            **case.coverage_by_ref,
            **{
                str(row.source_event_id): coverage_for_channel(PublicationChannel.HOOK_OBSERVED)
                for row in (*actions.values(), *results.values())
            },
        },
    )

    def first(
        frozen: DeterministicCase, content: Sequence[CapturedSemanticContent] = resolved.content
    ) -> tuple[str, bytes, bytes]:
        """The first packet's excerpt of the capture: its source ref, label line and body."""

        built = _build(
            frozen,
            captured_content=content,
            captured_content_scope=resolved.scope,
            workspace_root="/app",
        )
        (item,) = (item for item in built.items if b"native-output" in item.content)
        assert item.section == "excerpt"
        label, _, body = item.content.partition(b"\n")
        return item.source_ref, label, body

    source_ref, label, body = first(hooked)
    # A Codex hook post states no exit (#1105): the hook's own result reads ``unknown``, and the
    # label names that outcome and no exit status. The label names the excerpt's own source ref,
    # so the instruction's trust rule applies.
    assert (result.outcome, result.exit_status) == (ResultOutcome.UNKNOWN, None)
    assert (
        label
        == (
            f"[FinishUP: observed output captured by a host hook (evidence {source_ref}); run of "
            f"command action {action_ref}, host-reported outcome unknown"
            "; not an agent-published result]"
        ).encode()
    )
    assert b"12 passed native-output" in body
    # The session-stream item that states the exit joins the hook call as a corrected result of
    # the same action; the run then names the outcome and exit status the host reported.
    corrected_id = result_id("res_00000000-0000-4000-8000-000000001108")
    corrected = record(
        replace(
            result,
            result_id=corrected_id,
            outcome=ResultOutcome.SUCCESS,
            exit_status=0,
            evidence_refs=(),
        ),
        max(row.source_frontier for row in results.values()) + 1,
    )
    observed = coverage_for_channel(PublicationChannel.HOOK_OBSERVED)
    joined = replace(
        hooked,
        projection=replace(
            hooked.projection, results={**hooked.projection.results, corrected_id: corrected}
        ),
        allowed_ids=hooked.allowed_ids | {corrected_id, corrected.source_event_id},
        coverage_by_ref={
            **hooked.coverage_by_ref,
            corrected_id: observed,
            corrected.source_event_id: observed,
        },
    )
    assert first(joined) == (
        source_ref,
        (
            f"[FinishUP: observed output captured by a host hook (evidence {source_ref}); run of "
            f"command action {action_ref}, host-reported outcome success"
            ", exit status 0; not an agent-published result]"
        ).encode(),
        body,
    )

    plain = (
        f"[FinishUP: observed output captured by a host hook (evidence {source_ref}); "
        "not an agent-published result]"
    ).encode()
    # Records the host did not observe lend the capture no outcome: the label stays, the run
    # clause does not.
    assert first(case)[1:] == (plain, body)
    # Nor does an action whose command is plaintext rather than the keyed observed identity, or a
    # capture resolved under another identity.
    plaintext = {
        ref: record(replace(row.payload, command="pytest -q"), row.source_frontier)
        for ref, row in actions.items()
        if row.payload is not None
    }
    forged = replace(hooked, projection=replace(hooked.projection, actions=plaintext))
    assert first(forged)[1:] == (plain, body)
    mismatched = tuple(
        replace(item, observed_command_identity="omitted:hmac-sha256:" + "0" * 64)
        for item in resolved.content
    )
    assert first(hooked, mismatched)[1:] == (plain, body)
