"""Projection repair remains derived from immutable accepted history."""

from __future__ import annotations

import pytest

from conformance.adapters.test_ledger_port import ledger_command, sqlite_ledger
from finishup.kernel.projections import ProjectionState, projection_digest
from finishup.ports.ledger import ProjectionView


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_missing_projection_rebuilds_from_ledger() -> None:
    command = ledger_command()
    repository = sqlite_ledger(command)
    await repository.append_batch(command)
    await repository.rebuild_projection("work")
    stored = await repository.load_projection(command.session_id, ProjectionView.CANDIDATE_FINDINGS)
    assert stored is not None
    assert type(stored.state) is ProjectionState
    assert projection_digest(stored.state).startswith("sha256:")


@pytest.mark.anyio
async def test_rebuild_does_not_mutate_ledger_history() -> None:
    command = ledger_command()
    repository = sqlite_ledger(command)
    await repository.append_batch(command)
    before = tuple([row async for row in repository.load_events(command.session_id)])
    await repository.rebuild_projection("work")
    after = tuple([row async for row in repository.load_events(command.session_id)])
    assert after == before
