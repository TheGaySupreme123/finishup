"""Readiness doubles for the Stop gate: the ``rechecks`` list status announces (tb4n3 RC-8).

The gate reads ``closure_readiness`` by attribute, so tests hand it ``SimpleNamespace`` objects
shaped like the status wire. A re-check is built here once, with the content key the service
mints (``ack:<obligation>``, ``blocker:<obligation>:<kind>``, ``premise:<n>``), so no test
restates the key grammar. ``acceptance_recheck`` is the entry an earlier 0.3 service still
announces (``accept:<h8 of sorted resolved ids>``); since ADR-033 owner decision D1 the gate drops
it, and tests use it to prove that.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from types import SimpleNamespace
from typing import Any

OBLIGATION = "obl_97700000-0000-4000-8000-{index:012d}"
# The closed gate item the retired acceptance re-read added (before D1); never produced now.
ACCEPTANCE_RECHECK_ITEM = "acceptance_recheck"


def obligation_id(index: int) -> str:
    return OBLIGATION.format(index=index)


def recheck(
    kind: str, key: str, *, subjects: Sequence[str] = (), rule: str = "test", since: int = 1
) -> Any:
    return SimpleNamespace(
        kind=kind, key=key, subjects=tuple(subjects), rule=rule, since_frontier=str(since)
    )


def blocker_recheck(
    obligation: str = obligation_id(1), kind: str = "dependency_unavailable", *, since: int = 1
) -> Any:
    return recheck("blocker", f"blocker:{obligation}:{kind}", subjects=(obligation,), since=since)


def ack_recheck(obligation: str = obligation_id(100), *, since: int = 1) -> Any:
    return recheck("acknowledgement", f"ack:{obligation}", subjects=(obligation,), since=since)


def premise_recheck(count: int = 1, *, since: int = 1) -> Any:
    return recheck("premise", f"premise:{count}", since=since)


def acceptance_key(resolved: Sequence[str]) -> str:
    digest = hashlib.sha256("\n".join(sorted(resolved)).encode("ascii")).hexdigest()[:8]
    return f"accept:{digest}"


def acceptance_recheck(
    resolved: Sequence[str] = (obligation_id(200), obligation_id(201)), *, since: int = 1
) -> Any:
    """The ``acceptance`` entry an earlier 0.3 service announces; never asked since D1."""

    return recheck("acceptance", acceptance_key(resolved), subjects=tuple(resolved), since=since)


def readiness(
    state: str = "action_required",
    actionable: Sequence[str] = ("obligations_open",),
    *,
    rechecks: Sequence[Any] | None = (),
    **extra: Any,
) -> Any:
    """A readiness double; ``rechecks=None`` omits the list (a service older than the gate)."""

    fields: dict[str, Any] = {
        "state": state,
        "agent_actionable": tuple(actionable),
        "open_obligation_count": "2",
        "receipt_blocking_finding_count": "1",
    }
    if rechecks is not None:
        fields["rechecks"] = tuple(rechecks)
    fields.update(extra)
    return SimpleNamespace(**fields)
