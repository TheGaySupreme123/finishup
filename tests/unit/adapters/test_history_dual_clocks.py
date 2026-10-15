"""History projection exposes both caller-claimed time and service acceptance time.

Plan #07 / issue #78: ``status view=history`` must not present ``occurred_at`` alone as if it
were a service timestamp. Ordering remains ingestion sequence.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from builders.replay import replay_records
from finishup.domain.events import accepted_record_digest_preimage
from finishup.domain.values import occurred_at_consistency, timestamp_from_string
from finishup.mcp.descriptors import descriptor_for
from finishup.ports.ledger import ProjectionQuery
from finishup.protocol.canonical import JsonValue, entry_digest
from finishup.protocol.models import (
    StatusHistoryItemModel,
    StatusHistoryPageModel,
    classify_result_leaf,
)
from integration.storage.test_append_and_replay import command_from_records, memory_for


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_history_exposes_exact_occurred_and_accepted_at_in_ingestion_order() -> None:
    """Far-past / reversed caller timestamps stay claims; history shows both clocks in sequence order."""

    records = replay_records("wall-clock-reversal")
    command, objects = command_from_records(records, expected_frontier=0)
    ledger = memory_for(command, objects)
    result = await ledger.append_batch(command)
    assert result.outcome == "accepted"

    page = await ledger.query_projection(
        ProjectionQuery(
            command.session_id,
            "history",
            None,
            result.result_frontier,
            100,
            None,
            None,
        )
    )
    items = tuple(cast(StatusHistoryItemModel, item) for item in page.items)
    assert len(items) == len(records)

    # Ingestion sequence order is authoritative even when wall clocks reverse.
    sequences = tuple(int(item.ingestion_sequence) for item in items)
    assert sequences == tuple(range(1, len(records) + 1))
    assert sequences == tuple(record.ledger.ingestion_sequence for record in records)
    assert tuple(item.event_id for item in items) == tuple(record.event_id for record in records)

    # Append re-stamps trusted-local accepted_at from the service clock; caller occurred_at
    # is preserved exactly from the draft. Both clocks must appear on every history item.
    live_events = tuple([event async for event in ledger.load_events(command.session_id)])
    assert len(live_events) == len(records)
    for item, draft_record, live in zip(items, records, live_events, strict=True):
        assert item.occurred_at == draft_record.occurred_at.wire
        assert item.accepted_at == live.ledger.accepted_at.wire
        # FixedClock in the memory harness stamps acceptance independently of caller time.
        assert item.accepted_at == "2026-07-19T12:00:00.000Z"
        assert item.occurred_at != item.accepted_at
        assert item.occurred_at_consistency == "within_forward_skew_allowance"

    # Caller times reverse while sequence advances — proof order is not wall-clock.
    occurred = tuple(item.occurred_at for item in items)
    assert occurred == tuple(sorted(occurred, reverse=True))
    assert sequences == tuple(sorted(sequences))


@pytest.mark.anyio
async def test_far_past_and_future_caller_timestamps_remain_claims() -> None:
    """No skew policy: far-past and future occurred_at values are accepted and projected as claims."""

    records = replay_records("projection-rebuild")[:2]
    far_past = "1990-01-01T00:00:00.000Z"
    future = "2099-12-31T23:59:59.000Z"
    command, objects = command_from_records(records, expected_frontier=0)
    # Mutate only draft occurred_at claims — append does not recompute entry digests from fixtures.
    rewritten = tuple(
        replace(entry, draft=replace(entry.draft, occurred_at=timestamp_from_string(claim)))
        for entry, claim in zip(command.entries, (far_past, future), strict=True)
    )
    command = replace(command, entries=rewritten)
    ledger = memory_for(command, objects)
    result = await ledger.append_batch(command)
    assert result.outcome == "accepted"

    page = await ledger.query_projection(
        ProjectionQuery(
            command.session_id,
            "history",
            None,
            result.result_frontier,
            10,
            None,
            None,
        )
    )
    items = tuple(cast(StatusHistoryItemModel, item) for item in page.items)
    assert tuple(item.occurred_at for item in items) == (far_past, future)
    assert all(item.accepted_at == "2026-07-19T12:00:00.000Z" for item in items)
    assert tuple(item.occurred_at_consistency for item in items) == (
        "within_forward_skew_allowance",
        "ahead_of_forward_skew_allowance",
    )
    assert tuple(int(item.ingestion_sequence) for item in items) == (1, 2)


@pytest.mark.anyio
async def test_history_item_accepted_at_is_structural_metadata() -> None:
    """Privacy projection treats accepted_at as public structural metadata, not content."""

    records = replay_records("wall-clock-reversal")[:1]
    command, objects = command_from_records(records, expected_frontier=0)
    ledger = memory_for(command, objects)
    result = await ledger.append_batch(command)
    page = await ledger.query_projection(
        ProjectionQuery(
            command.session_id,
            "history",
            None,
            result.result_frontier,
            10,
            None,
            None,
        )
    )
    item = cast(StatusHistoryItemModel, page.items[0])
    # Minimal success shell: classify_result_leaf only needs ok, view, and the leaf path.
    wire: dict[str, JsonValue] = {
        "ok": True,
        "view": "history",
        "page": {
            "items": [cast(JsonValue, item.model_dump(mode="json"))],
            "next_cursor": None,
        },
    }
    assert classify_result_leaf("status", wire, "/page/items/0/accepted_at") == "public_structural"
    assert classify_result_leaf("status", wire, "/page/items/0/occurred_at") == "public_structural"
    assert (
        classify_result_leaf("status", wire, "/page/items/0/occurred_at_consistency")
        == "public_structural"
    )


def test_occurred_at_consistency_uses_closed_five_second_forward_allowance() -> None:
    accepted = timestamp_from_string("2026-07-19T12:00:00.000Z")
    boundary = timestamp_from_string("2026-07-19T12:00:05.000Z")
    beyond = timestamp_from_string("2026-07-19T12:00:05.001Z")

    assert occurred_at_consistency(boundary, accepted) == "within_forward_skew_allowance"
    assert occurred_at_consistency(beyond, accepted) == "ahead_of_forward_skew_allowance"


def test_occurred_at_consistency_handles_the_timestamp_ceiling() -> None:
    accepted = timestamp_from_string("9999-12-31T23:59:59.000Z")
    occurred = timestamp_from_string("9999-12-31T23:59:59.999Z")

    assert occurred_at_consistency(occurred, accepted) == "within_forward_skew_allowance"


def test_entry_digest_still_binds_occurred_at_and_accepted_at() -> None:
    """Entry digests continue to bind both clocks; neither is ornamental."""

    record = replay_records("wall-clock-reversal")[0]
    preimage = accepted_record_digest_preimage(record)
    assert preimage["occurred_at"] == record.occurred_at.wire
    ledger = cast(dict[str, object], preimage["ledger"])
    assert ledger["accepted_at"] == record.ledger.accepted_at.wire
    assert entry_digest(preimage) == record.entry_digest

    mutated: dict[str, JsonValue] = dict(cast(dict[str, JsonValue], preimage))
    mutated["occurred_at"] = "1999-01-01T00:00:00.000Z"
    assert entry_digest(mutated) != record.entry_digest

    mutated_ledger = dict(cast(dict[str, JsonValue], preimage["ledger"]))
    mutated_ledger["accepted_at"] = "1999-01-01T00:00:00.000Z"
    mutated2: dict[str, JsonValue] = dict(cast(dict[str, JsonValue], preimage))
    mutated2["ledger"] = mutated_ledger
    assert entry_digest(mutated2) != record.entry_digest


def test_history_item_schema_requires_both_clocks() -> None:
    item = {
        "event_id": "evt_00000000-0000-4000-8000-000000000001",
        "schema_name": "plan_published",
        "schema_version": "1.0.0",
        "actor_id": "harness:test",
        "publication_channel": "cooperative_mcp",
        "ingestion_sequence": "1",
        "occurred_at": "2026-03-06T12:00:03.000Z",
        "accepted_at": "2026-03-06T18:30:00.000Z",
        "occurred_at_consistency": "within_forward_skew_allowance",
        "projection_status": "projected",
        "summary_code": "plan_published",
    }
    StatusHistoryItemModel.model_validate(item)
    StatusHistoryPageModel.model_validate({"items": [item], "next_cursor": None})

    missing = dict(item)
    del missing["accepted_at"]
    with pytest.raises(Exception):
        StatusHistoryItemModel.model_validate(missing)

    missing_consistency = dict(item)
    del missing_consistency["occurred_at_consistency"]
    with pytest.raises(Exception):
        StatusHistoryItemModel.model_validate(missing_consistency)


def test_event_draft_schema_describes_occurred_at_as_claim() -> None:
    from finishup.domain.events import OCCURRED_AT_DRAFT_DESCRIPTION

    for relative in (
        "schemas/events/event-draft-1.0.0.schema.json",
        "schemas/events/event-draft-1.1.0.schema.json",
        "schemas/events/opaque-unknown-event-draft-1.0.0.schema.json",
        "schemas/events/opaque-unknown-event-draft-1.1.0.schema.json",
    ):
        draft = json.loads(Path(relative).read_text(encoding="utf-8"))
        occurred = draft["properties"]["occurred_at"]
        assert occurred["description"] == OCCURRED_AT_DRAFT_DESCRIPTION
        text = occurred["description"].lower()
        assert "caller-asserted" in text
        assert "do not copy" in text
        assert "ingestion sequence" in text
        assert "frontier-bound" in text
        assert "accepted_at" in text
        # Freshness must not be described as accepted_at wall-clock age.
        assert "freshness use" not in text
        assert "freshness uses" not in text


def test_publish_and_status_descriptors_distinguish_clocks() -> None:
    publish = descriptor_for("publish_work").description.lower()
    status = descriptor_for("status").description.lower()
    assert "illustrative example timestamp" in publish
    assert "caller-asserted" in publish
    assert "accepted_at" in publish
    assert "ingestion sequence" in publish
    assert "frontier-bound" in publish
    assert "occurred_at" in status
    assert "accepted_at" in status
    assert "forward-skew classification" in status
    assert "ingestion sequence" in status
    # Must not instruct agents that FinishUP checked outside event time.
    assert "verified" not in publish
    assert "verified" not in status
    # Must not claim receipt freshness comes from accepted_at wall-clock.
    assert "freshness come from ingestion sequence and service accepted_at" not in publish
