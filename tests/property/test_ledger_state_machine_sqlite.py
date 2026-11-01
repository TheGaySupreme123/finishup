"""SQLite ledger state-machine checks against the memory oracle."""

from __future__ import annotations

import pytest

from conformance.adapters.test_ledger_port import ledger_command, memory_ledger, sqlite_ledger
from finishup.ports.ledger import ProjectionView


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_sqlite_matches_memory_start_and_append_rules() -> None:
    command = ledger_command()
    memory = memory_ledger(command)
    sqlite = sqlite_ledger(command)
    assert await sqlite.append_batch(command) == await memory.append_batch(command)
    assert await sqlite.append_batch(command) == await memory.append_batch(command)


@pytest.mark.anyio
async def test_sqlite_projection_and_recovery_rules_match_model() -> None:
    command = ledger_command()
    memory = memory_ledger(command)
    sqlite = sqlite_ledger(command)
    await memory.append_batch(command)
    await sqlite.append_batch(command)
    memory_projection = await memory.load_projection(
        command.session_id, ProjectionView.CANDIDATE_FINDINGS
    )
    sqlite_projection = await sqlite.load_projection(
        command.session_id, ProjectionView.CANDIDATE_FINDINGS
    )
    assert sqlite_projection == memory_projection
