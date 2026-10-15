"""Composition-level structural progress for durable AI-powered review jobs (issue #571 A2).

Drives the real ``_privacy_gated_semantic_evaluator`` over memory and SQLite ledgers. The fake
privacy coordinator stands where the gateway and provider report phases, and reads the durable
progress row while its attempt is still in flight, so the test observes live progress exactly as
``status view=operation`` would, then the single terminal state after the job ends.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

import pytest

import integration.service.test_semantic_fallback_dispatch as fallback_dispatch
from builders.ledger_adapters import FixedClock, append_command, memory_adapter, sqlite_adapter
from finishup.adapters.memory.ledger import MemoryLedgerAdapter
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.observability.semantic_context import report_semantic_progress
from finishup.ports.ledger import SemanticProgressRecord
from finishup.protocol.models import SemanticProgressPhase, SemanticReason, SemanticStatus

_PairedPrivacy = fallback_dispatch._PairedPrivacy  # pyright: ignore[reportPrivateUsage]
_paired_evaluator = fallback_dispatch._paired_evaluator  # pyright: ignore[reportPrivateUsage]
_durable_semantic_case = fallback_dispatch._durable_semantic_case  # pyright: ignore[reportPrivateUsage]


class _ObservingPrivacy(_PairedPrivacy):
    """Reports provider phases for each attempt and snapshots the durable row mid-flight."""

    def __init__(self, adapter: MemoryLedgerAdapter | SqliteLedger, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.adapter = adapter
        self.writer_id = ""
        self.operation_id = ""
        self.in_flight: list[SemanticProgressRecord | None] = []

    async def evaluate_semantic(self, candidate: object, deadline: object) -> object:
        await report_semantic_progress(SemanticProgressPhase.CASE_ADMITTED)
        await report_semantic_progress(SemanticProgressPhase.PROVIDER_SAMPLING)
        self.in_flight.append(
            await self.adapter.load_semantic_progress(self.writer_id, self.operation_id)
        )
        return await super().evaluate_semantic(candidate, deadline)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "adapter_factory",
    (memory_adapter, sqlite_adapter),
    ids=("memory", "sqlite"),
)
async def test_live_phases_follow_each_attempt_and_end_in_one_terminal_state(
    adapter_factory: Callable[[object], MemoryLedgerAdapter | SqliteLedger],
) -> None:
    adapter = adapter_factory(append_command())
    frozen, runtime = await _durable_semantic_case(adapter)
    privacy = _ObservingPrivacy(adapter, task_id=runtime.task_id)
    privacy.writer_id = frozen.lease.writer_id
    privacy.operation_id = frozen.lease.operation_id
    clock = FixedClock()

    result = await _paired_evaluator(privacy, runtime, clock=clock)(frozen, (), runtime)

    assert (result.status, result.reason) == (
        SemanticStatus.SUCCEEDED,
        SemanticReason.SEMANTIC_COMPLETED,
    )
    now = clock.now_utc()
    deadline_at = now + timedelta(seconds=120)
    # Every physical attempt was observed live at its own ordinal while sampling.
    assert [
        (row.attempt_ordinal, row.phase, row.queued_at, row.deadline_at)
        for row in privacy.in_flight
        if row is not None
    ] == [
        (ordinal, SemanticProgressPhase.PROVIDER_SAMPLING, now, deadline_at)
        for ordinal in (1, 2, 3)
    ]
    terminal = await adapter.load_semantic_progress(
        frozen.lease.writer_id, frozen.lease.operation_id
    )
    assert terminal is not None
    assert terminal.phase is SemanticProgressPhase.TERMINAL
    assert terminal.attempt_ordinal == 3
    assert terminal.terminal_outcome == "succeeded"
    assert terminal.terminal_reason is SemanticReason.SEMANTIC_COMPLETED
    assert (terminal.queued_at, terminal.deadline_at) == (now, deadline_at)
