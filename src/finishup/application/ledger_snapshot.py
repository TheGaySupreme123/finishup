"""Reuse the ledger's trusted projection at an exact frontier; replay older prefixes off-loop."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Awaitable, Callable
from typing import cast

from finishup.domain.events import LedgerRecord
from finishup.domain.values import Frontier
from finishup.kernel.projections import ProjectionState, empty_projection_state
from finishup.kernel.reducers import empty_replay_index, extend_replay_index, reduce_event
from finishup.ports.ledger import LedgerPort, ProjectionView


class ReplayCancelled(Exception):
    """The awaiting caller went away; the worker stopped folding at the next record."""


def _replay_until_cancelled(
    records: tuple[LedgerRecord, ...], cancelled: threading.Event
) -> ProjectionState:
    state = empty_projection_state()
    index = empty_replay_index()
    for event in records:
        if cancelled.is_set():
            raise ReplayCancelled
        index = extend_replay_index(index, event)
        state = reduce_event(state, event, index)
    return state


async def replay_off_loop(records: tuple[LedgerRecord, ...]) -> ProjectionState:
    """Genesis-replay ``records`` in a worker thread that stops promptly if the caller is cancelled.

    A plain ``asyncio.to_thread`` keeps a GIL-bound replay running after an RPC deadline cancels
    its caller, so a same-request retry doubled the CPU on small hosts (issue #886). The fold is
    pure; stopping it early discards nothing durable.
    """

    cancelled = threading.Event()
    worker = asyncio.get_running_loop().run_in_executor(
        None, _replay_until_cancelled, records, cancelled
    )
    try:
        # ``asyncio.wait`` never cancels the worker itself, unlike awaiting it directly.
        await asyncio.wait((worker,))
    except asyncio.CancelledError:
        cancelled.set()
        # Join the worker so no replay outlives the request; it exits at the next record.
        try:
            await worker
        except ReplayCancelled, ValueError:
            pass
        raise
    return worker.result()


async def trusted_projection_at(
    ledger: LedgerPort, session_id: str, frontier: Frontier
) -> ProjectionState | None:
    """Return the adapter-owned projection at exactly ``frontier`` without replaying, if any."""

    loader = getattr(ledger, "load_trusted_projection", None)
    if callable(loader):
        trusted = await cast(Callable[[str, Frontier], Awaitable[ProjectionState | None]], loader)(
            session_id, frontier
        )
        if (
            type(trusted) is ProjectionState
            and Frontier(trusted.frontier, trusted.head_digest) == frontier
        ):
            return trusted
    if callable(getattr(ledger, "load_projection", None)):
        stored = await ledger.load_projection(session_id, ProjectionView.CANDIDATE_FINDINGS)
        if (
            stored is not None
            and not stored.rebuild_required
            and stored.lag == 0
            and stored.frontier == frontier
            and type(stored.state) is ProjectionState
            and Frontier(stored.state.frontier, stored.state.head_digest) == frontier
        ):
            return stored.state
    return None


async def projection_for_records(
    ledger: LedgerPort,
    session_id: str,
    frontier: Frontier,
    records: tuple[LedgerRecord, ...],
) -> ProjectionState:
    """Reuse an adapter-owned projection at exactly ``frontier``; otherwise replay off-loop.

    No global cache retains task content. The adapter owns recovery, append and redaction
    invalidation: it vouches only for the live head or for a bounded set of recent frontiers whose
    exact record objects are still the chain prefix. Older snapshots and legacy embedders fall
    back to genesis-authenticated replay of immutable records, without carrying SQLite handles or
    mutable state into the worker.
    """

    trusted = await trusted_projection_at(ledger, session_id, frontier)
    if trusted is not None:
        return trusted
    return await replay_off_loop(records)
