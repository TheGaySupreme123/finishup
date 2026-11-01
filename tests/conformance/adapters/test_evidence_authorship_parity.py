"""Evidence authorship facts and ``author=mine`` agree on both ledger backends (issue #914).

The SQLite ledger answers status pages through the same frozen-prefix oracle as the memory ledger,
so both must attribute a readable evidence row to its source event, list it for its own writer
only, and withdraw the attribution when a later redaction targets that source event: a pinned
read replays its own prefix, and self-authorship must never re-disclose owner-redacted prose.
"""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import apsw
import pytest

from builders.replay import replay_records
from finishup.domain.events import (
    LedgerRecord,
    RedactionRecordedPayload,
    encode_payload,
    is_observation_authored,
)
from finishup.domain.privacy import SourceAuthorship
from finishup.domain.values import Frontier, object_id
from finishup.ports.ledger import AppendCommand, EvidenceProjectionFilter, ProjectionQuery
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.models import StatusEvidenceItemModel
from integration.storage.test_append_and_replay import command_from_records, memory_for, sqlite_for

pytestmark = pytest.mark.anyio

_OTHER_WRITER = "wri_91400000-0000-4000-8000-000000000001"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _object_only(command: AppendCommand, redaction: LedgerRecord, target: str) -> AppendCommand:
    """Retarget the fixture redaction at one payload object only, as an owner may record it."""

    entries = list(command.entries)
    index = next(i for i, entry in enumerate(entries) if entry.draft.event_id == redaction.event_id)
    payload = replace(
        cast(RedactionRecordedPayload, redaction.payload),
        target_event_ids=(),
        target_object_ids=(object_id(target),),
    )
    entries[index] = replace(
        entries[index],
        draft=replace(entries[index].draft, payload=payload, artifact_refs=(object_id(target),)),
    )
    return replace(command, entries=tuple(entries))


async def _page(
    backend: str,
    records: tuple[LedgerRecord, ...],
    frontier: int,
    writer: str | None,
    *,
    object_redaction: str | None = None,
) -> tuple[tuple[StatusEvidenceItemModel, ...], tuple[tuple[SourceAuthorship, ...], ...]]:
    command, objects = command_from_records(records, expected_frontier=0)
    if object_redaction is not None:
        redaction = next(row for row in records if row.schema.name == "redaction_recorded")
        command = _object_only(command, redaction, object_redaction)
        payload = next(
            entry.draft.payload
            for entry in command.entries
            if entry.draft.event_id == redaction.event_id
        )
        objects._data[redaction.payload_ref.object_id] = canonical_encode(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
            encode_payload(cast(RedactionRecordedPayload, payload))
        )
    db = apsw.Connection(":memory:") if backend == "sqlite" else None
    ledger = memory_for(command, objects) if db is None else sqlite_for(command, objects, db)
    try:
        await ledger.append_batch(command)
        accepted = tuple([row async for row in ledger.load_events(command.session_id)])
        target = next(row for row in accepted if row.ledger.ingestion_sequence == frontier)
        page = await ledger.query_projection(
            ProjectionQuery(
                command.session_id,
                "evidence",
                None if writer is None else EvidenceProjectionFilter(None, None, True, "mine"),
                Frontier(frontier, target.entry_digest),
                100,
                None,
                None,
                writer,
            )
        )
        items = tuple(item for item in page.items if type(item) is StatusEvidenceItemModel)
        return items, page.item_sources
    finally:
        if db is not None:
            db.close()


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_backends_attribute_list_and_withdraw_alike(backend: str) -> None:
    records = replay_records("all-event-families")
    redaction = next(row for row in records if row.schema.name == "redaction_recorded")
    source = next(
        row
        for row in records
        if row.schema.name == "evidence_recorded"
        and row.event_id in redaction.projection_locator.redaction_target_event_ids
    )
    before = redaction.ledger.ingestion_sequence - 1
    expected = SourceAuthorship(
        source.writer.writer_id,
        source.session_id,
        source.ledger.ingestion_sequence,
        source.publication_channel,
        is_observation_authored(source),
    )
    prefix = tuple(row for row in records if row.ledger.ingestion_sequence <= before)

    # Without the later redaction, the pinned row is attributed to its source event.
    items, sources = await _page(backend, prefix, before, None)
    assert [item.publication_channel for item in items] == [source.publication_channel.value]
    assert sources == ((expected,),)

    # With it, the same pinned read keeps the row but withdraws the attribution.
    items, sources = await _page(backend, records, before, None)
    assert len(items) == 1
    assert sources == ((),)

    # ``author=mine`` is decided from the same facts, for the source writer only.
    mine, _ = await _page(backend, prefix, before, source.writer.writer_id)
    assert [item.evidence_id for item in mine] == [item.evidence_id for item in items]
    other, _ = await _page(backend, prefix, before, _OTHER_WRITER)
    assert other == ()


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_a_later_object_redaction_of_the_source_payload_also_withdraws(backend: str) -> None:
    """Redacting the source event's payload object tombstones the row just like an event target."""

    records = replay_records("all-event-families")
    redaction = next(row for row in records if row.schema.name == "redaction_recorded")
    source = next(
        row
        for row in records
        if row.schema.name == "evidence_recorded"
        and row.event_id in redaction.projection_locator.redaction_target_event_ids
    )
    before = redaction.ledger.ingestion_sequence - 1
    items, sources = await _page(
        backend, records, before, None, object_redaction=source.payload_ref.object_id
    )
    assert len(items) == 1
    assert sources == ((),)
    # The unrelated captured-artifact object target keeps the row attributed: only the source
    # event's payload object carries the redacted prose.
    items, sources = await _page(
        backend,
        records,
        before,
        None,
        object_redaction=next(
            iter(
                set(redaction.projection_locator.redaction_target_object_ids)
                - {source.payload_ref.object_id}
            )
        ),
    )
    assert len(items) == 1
    assert sources != ((),)
