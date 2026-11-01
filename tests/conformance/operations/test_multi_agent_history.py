"""Current history projections must read the event families accepted by the ledger."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from builders.replay import replay_records
from finishup.domain.events import EVENT_FAMILIES
from finishup.ports.ledger import ProjectionQuery
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import StatusHistoryItemModel
from finishup.protocol.schemas import schema_document_for
from integration.storage.test_append_and_replay import (
    command_from_records,
    file_sqlite_for,
    memory_for,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize("adapter", ("memory", "sqlite"))
async def test_history_reads_accepted_lineage_and_coordination_events(
    tmp_path: Path, adapter: str
) -> None:
    records = replay_records("lineage-event-families")
    command, objects = command_from_records(records)
    db = None
    if adapter == "sqlite":
        ledger, db = file_sqlite_for(command, objects, tmp_path / "history.sqlite3")
    else:
        ledger = memory_for(command, objects)
    try:
        appended = await ledger.append_batch(command)
        assert appended.outcome == "accepted"
        page = await ledger.query_projection(
            ProjectionQuery(
                command.session_id, "history", None, appended.result_frontier, 100, None, None
            )
        )
        history = tuple(cast(StatusHistoryItemModel, item) for item in page.items)
        assert tuple(item.summary_code for item in history) == tuple(
            record.schema.name for record in records
        )
        assert all(item.projection_status == "projected" for item in history)
        assert tuple(item.event_id for item in history) == tuple(
            record.event_id for record in records
        )
    finally:
        if db is not None:
            db.close()


@pytest.mark.parametrize("family", EVENT_FAMILIES)
def test_history_wire_admits_every_registered_event_family(family: str) -> None:
    record = replay_records("lineage-event-families")[0]
    item = StatusHistoryItemModel.model_validate(
        {
            "event_id": record.event_id,
            "schema_name": family,
            "schema_version": record.schema.version,
            "actor_id": record.author.actor_id,
            "publication_channel": record.publication_channel.value,
            "ingestion_sequence": str(record.ledger.ingestion_sequence),
            "occurred_at": record.occurred_at.wire,
            "accepted_at": record.ledger.accepted_at.wire,
            "occurred_at_consistency": "within_forward_skew_allowance",
            "projection_status": "projected",
            "summary_code": family,
        }
    )
    assert item.summary_code == family


def test_packaged_history_schema_covers_registered_events() -> None:
    value: JsonValue = schema_document_for("status-result", "1.4.0").json_schema["$defs"]
    for key in ("history_item", "properties", "summary_code", "enum"):
        assert isinstance(value, Mapping)
        value = value[key]
    assert isinstance(value, tuple)
    assert set(value) == {*EVENT_FAMILIES, "opaque_unknown"}
