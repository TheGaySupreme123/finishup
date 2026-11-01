"""Reference capacity with real appended observation records, not unbacked extra IDs."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from builders.replay import replay_records
from finishup.application import ledger_snapshot
from finishup.application.semantic_case import bounded_case_envelope, build_semantic_case
from finishup.domain.events import (
    OBSERVATION_COORDINATOR_ACTOR_ID,
    ActionRecordedPayload,
    encode_payload,
    is_observation_authored,
)
from finishup.domain.privacy import (
    MAX_EGRESS_ENVELOPE_BYTES,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.domain.values import (
    Actor,
    ActorType,
    Frontier,
    action_id,
    actor_id,
    event_id,
    object_id,
)
from finishup.kernel.deterministic_checks import CaseAvailabilityFacts, build_deterministic_case
from finishup.kernel.projections import ProjectionState
from finishup.ports.ledger import AppendEntry, ProjectionView
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.coverage import AuthorshipAssurance, PublicationChannel, coverage_for_channel
from integration.storage.test_append_and_replay import command_from_records, memory_for, uuid_id


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.timeout(300)
async def test_observation_history_no_longer_forces_full_reference_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = replay_records("all-event-families")
    base, objects = command_from_records(fixture[:4], expected_frontier=0)
    ledger = memory_for(base, objects)
    await ledger.append_batch(base)
    template = next(row for row in fixture if isinstance(row.payload, ActionRecordedPayload))
    assert isinstance(template.payload, ActionRecordedPayload)
    template_command, _ = command_from_records((template,), objects=objects)
    entry = template_command.entries[0]
    for batch in range(16):
        entries: list[AppendEntry] = []
        for offset in range(100):
            number = 10000 + batch * 100 + offset
            payload = replace(template.payload, action_id=action_id(uuid_id("act", number)))
            data = canonical_encode(encode_payload(payload))
            ref = replace(
                entry.payload_object,
                object_id=object_id(uuid_id("obj", number)),
                plaintext_size=len(data),
            )
            objects._data[ref.object_id] = data  # pyright: ignore[reportPrivateUsage]
            entries.append(
                replace(
                    entry,
                    draft=replace(
                        entry.draft,
                        event_id=event_id(uuid_id("evt", number)),
                        causal_parents=(),
                        payload=payload,
                    ),
                    author=Actor(
                        actor_id(OBSERVATION_COORDINATOR_ACTOR_ID),
                        ActorType.HARNESS,
                        AuthorshipAssurance.HARNESS_OBSERVED,
                    ),
                    payload_object=ref,
                    plaintext_size=len(data),
                    publication_channel=PublicationChannel.HOOK_OBSERVED,
                    coverage=coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
                )
            )
        operation_id = uuid_id("req", batch + 100)
        command = replace(
            base,
            operation_id=operation_id,
            expected_frontier=4 + batch * 100,
            entries=tuple(entries),
            request_digest=canonical_digest({"operation_id": operation_id, "batch": batch}),
        )
        await ledger.append_batch(command)
    records = tuple([row async for row in ledger.load_events(base.session_id)])
    assert all(is_observation_authored(row) for row in records[4:])
    snapshot = await ledger.load_projection(base.session_id, ProjectionView.CANDIDATE_FINDINGS)
    assert snapshot is not None and type(snapshot.state) is ProjectionState

    def forbidden_replay(*_args: object) -> ProjectionState:
        pytest.fail("mature current snapshot must not replay observation history")

    monkeypatch.setattr(ledger_snapshot, "_replay_until_cancelled", forbidden_replay)
    frontier = Frontier(snapshot.state.frontier, snapshot.state.head_digest)
    for _ in range(10):
        assert (
            await ledger_snapshot.projection_for_records(ledger, base.session_id, frontier, records)
            is snapshot.state
        )
    # Freeze through the public builder, retaining its full independent chain/projection replay.
    # The append-built projection is already available; replaying it first would duplicate that.
    frozen = build_deterministic_case(snapshot.state, records, CaseAvailabilityFacts())
    # The old irreducible reference array alone exceeded the unchanged whole-packet bound.
    assert (
        len(canonical_encode(cast(JsonValue, sorted(frozen.allowed_ids))))
        > MAX_EGRESS_ENVELOPE_BYTES
    )
    semantic = build_semantic_case(
        case_id=uuid_id("cas", 1),
        frozen_case=frozen,
        dependency_digest="sha256:" + "a" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.STRUCTURAL,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        policy_id=uuid_id("pvy", 1),
        policy_version="1",
    )
    packet = bounded_case_envelope(semantic)
    assert len(packet) <= MAX_EGRESS_ENVELOPE_BYTES
    assert semantic.omitted_reference_count > 0
    assert len(semantic.frontier_refs) + semantic.omitted_reference_count == len(frozen.allowed_ids)
    assert "semantic_reference_scope_reduced" in semantic.packet.coverage.known_gaps
    assert set(semantic.frontier_refs) <= set(frozen.allowed_ids)
    parsed = strict_json_parse(packet)
    assert isinstance(parsed, dict)
    assert parsed["omitted_reference_count"] == str(semantic.omitted_reference_count)
    assert bounded_case_envelope(semantic) == packet
