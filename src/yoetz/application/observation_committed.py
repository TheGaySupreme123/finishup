"""One definition of "this observation is already in the task ledger" (#1027).

Three decisions in the observation coordinator ask whether an observation is already committed:
the Codex stream-generation alignment (#1019), the paired-call action link (#917), and the
replay/duplicate classification of an append the ledger would refuse. They used to ask through
different reads (the projected action, a role-set operation digest, and nothing at all for the
refusal), so a delivery that was committed under another role-set shape was invisible to the
append and was quarantined as a content refusal (tb4n3 N3-7: 183 lost command outcomes).

The answer is the ledger's own: an event id is committed when the task ledger holds a record with
that id. Event ids are derived from the task, the keyed call identity and the role, never from the
shape of the delivery, so this is true for a hook copy, a stream copy, a content-bearing and a
contentless delivery alike.

The reads are optional ledger seams, like ``projected_action_event``: an in-process ledger or
test double without one reports nothing committed, which is the behavior before this module.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from typing import cast

__all__ = [
    "action_event_committed",
    "committed_event_ids",
    "observation_already_committed",
]


async def committed_event_ids(ledger: object, event_ids: Iterable[str]) -> frozenset[str]:
    """Return which of ``event_ids`` the task ledger already holds."""

    wanted = tuple(dict.fromkeys(str(item) for item in event_ids))
    if not wanted:
        return frozenset()
    probe = getattr(ledger, "committed_event_ids", None)
    if not callable(probe):
        return frozenset()
    found = await cast(Callable[[tuple[str, ...]], Awaitable[Iterable[str]]], probe)(wanted)
    return frozenset(str(item) for item in found) & frozenset(wanted)


async def observation_already_committed(ledger: object, event_ids: Iterable[str]) -> bool:
    """True when every one of ``event_ids`` is already in the ledger and there is at least one.

    A partially committed batch is not a duplicate: the ledger refuses it whole, and the refusal
    stays a content refusal.
    """

    wanted = frozenset(str(item) for item in event_ids)
    return bool(wanted) and await committed_event_ids(ledger, wanted) == wanted


async def action_event_committed(ledger: object, action: str, action_event: str) -> bool:
    """True when the task projection records ``action`` through exactly ``action_event``.

    The paired-call link and the generation alignment name an action by the event that records
    it, so the projection's source event (not mere presence of the id) is the fact they need.
    A ledger without the projection read answers from the event ids alone.
    """

    lookup = getattr(ledger, "projected_action_event", None)
    if callable(lookup):
        return await cast(Callable[[str], Awaitable[str | None]], lookup)(action) == action_event
    return await observation_already_committed(ledger, (action_event,))
