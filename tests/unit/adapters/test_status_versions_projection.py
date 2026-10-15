"""status view=versions uses the shared live runtime producer, not historical literals."""

from __future__ import annotations

from types import MappingProxyType
from typing import cast

import pytest

from builders.replay import replay_records
from finishup.ports.ledger import ProjectionQuery
from finishup.protocol.models import StatusVersionSliceModel
from finishup.version import build_status_version_slice_facts
from integration.storage.test_append_and_replay import command_from_records, memory_for


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_versions_projection_matches_version_producer_not_historical_literals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "finishup.version._runtime_components",
        lambda: (
            MappingProxyType({"status": "present", "version": "9.9.9.9"}),
            MappingProxyType({"status": "present", "version": "9.9.9"}),
            MappingProxyType({"status": "present", "source_id": "probe-sqlite-source-id"}),
            MappingProxyType({"status": "present", "digest": "sha256:" + "ab" * 32}),
        ),
    )
    records = replay_records("wall-clock-reversal")
    command, objects = command_from_records(records, expected_frontier=0)
    ledger = memory_for(command, objects)
    result = await ledger.append_batch(command)
    assert result.outcome == "accepted"

    page = await ledger.query_projection(
        ProjectionQuery(
            command.session_id,
            "versions",
            None,
            result.result_frontier,
            1,
            None,
            None,
        )
    )
    item = cast(StatusVersionSliceModel, page.items[0])
    facts = build_status_version_slice_facts()

    assert item.apsw_version == facts.apsw_version == "9.9.9.9"
    assert item.sqlite_version == facts.sqlite_version == "9.9.9"
    assert item.sqlite_source_id == facts.sqlite_source_id == "probe-sqlite-source-id"
    assert item.projection_version == facts.projection_version == "yoetz/0.1.0"
    assert item.apsw_version != "3.51.0.0"
    assert item.sqlite_version != "3.51.0"
    assert item.provider_profiles == facts.provider_profiles
