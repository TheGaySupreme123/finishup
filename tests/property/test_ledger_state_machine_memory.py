"""Generated idempotency/frontier sequences for the memory ledger oracle."""

from __future__ import annotations

import pytest

from conformance.adapters.test_ledger_port import ledger_command, memory_ledger
from finishup.protocol.errors import PublicErrorCode, PublicOperationError


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_memory_state_machine_append_and_freeze() -> None:
    command = ledger_command()
    adapter = memory_ledger(command)
    first = await adapter.append_batch(command)
    for _ in range(8):
        replay = await adapter.append_batch(command)
        assert replay.outcome == "replayed"
        assert replay.accepted == first.accepted
    rows = tuple([row async for row in adapter.load_events(command.session_id)])
    assert len(rows) == 1


@pytest.mark.anyio
async def test_memory_state_machine_check_and_receipt() -> None:
    command = ledger_command()
    adapter = memory_ledger(command)
    await adapter.append_batch(command)
    stale = ledger_command(request_suffix="2")
    with pytest.raises(PublicOperationError) as caught:
        await adapter.append_batch(stale)
    assert caught.value.code is PublicErrorCode.FRONTIER_CONFLICT
