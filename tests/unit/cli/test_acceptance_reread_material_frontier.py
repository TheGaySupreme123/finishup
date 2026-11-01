"""An acceptance entry from an earlier service is never asked, across invocations and deltas (D1).

Before ADR-033 owner decision D1 the acceptance re-read was remembered in the observation-state
file (``accept:<h8>@<invite>[@m<material>]``) and asked again after a material delta. Since D1 the
gate never asks it: not at the first invocation, not after the ledger or the material frontier
moves, and never writes an ``accept:`` key. The invite frontier of a key an earlier build wrote
still decides which acknowledgement answered that invite, read from the file by a later
invocation.
"""

from __future__ import annotations

from pathlib import Path

from builders.gate_readiness import (
    ACCEPTANCE_RECHECK_ITEM,
    acceptance_recheck,
    ack_recheck,
    readiness,
)
from finishup.cli.closure_gate import (
    ACKNOWLEDGEMENT_RECHECK_ITEM,
    ClosureGate,
    closure_gate_from_readiness,
    closure_gate_reasked_blockers,
    record_closure_gate_delivered,
)

_DIGEST = "sha256:" + "a" * 64
_SESSION = "ses_material_frontier"


def _decide(
    sequence: str,
    material: str | None,
    memory: frozenset[str],
    *,
    rechecks: tuple[object, ...] | None = None,
) -> ClosureGate | None:
    invite = acceptance_recheck()
    extra: dict[str, object] = {}
    if material is not None:
        extra["closing_material_frontier"] = material
    value = readiness(
        "ready_with_limitations",
        (),
        rechecks=(invite,) if rechecks is None else rechecks,
        acknowledged_obligation_count="0",
        receipt_blocking_finding_count="0",
        **extra,
    )
    return closure_gate_from_readiness(
        value,
        frontier_sequence=sequence,
        frontier_digest=_DIGEST,
        observation_pending=False,
        reasked_blockers=memory,
    )


def test_an_older_service_acceptance_entry_is_never_asked_across_invocations_and_deltas(
    tmp_path: Path,
) -> None:
    invite = acceptance_recheck()
    for sequence, material in (("10", "3"), ("14", "3"), ("21", "7"), ("30", None)):
        assert _decide(sequence, material, frozenset()) is None
        remembered = closure_gate_reasked_blockers(_SESSION, _state=tmp_path)
        assert _decide(sequence, material, remembered) is None

    # A key an earlier build wrote is read back by a later invocation: its invite frontier is the
    # decimal before ``@m``, so an acknowledgement after it is not challenged, and one published
    # before it still is, once, without any acceptance item or key.
    assert record_closure_gate_delivered(
        _SESSION, f"10:{_DIGEST}", blocker_keys=(f"{invite.key}@10@m3",), _state=tmp_path
    )
    remembered = closure_gate_reasked_blockers(_SESSION, _state=tmp_path)
    assert remembered == frozenset({f"{invite.key}@10@m3"})
    assert _decide("22", "7", remembered, rechecks=(invite, ack_recheck(since=11))) is None
    earlier = _decide("22", "7", remembered, rechecks=(invite, ack_recheck(since=9)))
    assert earlier is not None
    assert ACCEPTANCE_RECHECK_ITEM not in earlier.items
    assert earlier.items == (ACKNOWLEDGEMENT_RECHECK_ITEM,)
    assert not any(key.startswith("accept:") for key in earlier.blocker_keys)
    # The older prefix-only key (no ``@m``) keeps the same meaning.
    legacy = frozenset({f"{invite.key}@10"})
    assert _decide("30", None, legacy, rechecks=(invite, ack_recheck(since=11))) is None
