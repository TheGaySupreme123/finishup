"""An acceptance re-read is remembered in the observation-state file, not in the process.

Two gate decisions share only that file. The same flagged set is not asked again while
``closing_material_frontier`` is unchanged, including when the ledger frontier moves. A higher
material frontier asks it again. A key written before the ``@m`` suffix does not suppress the
ask. Status that omits the field keeps the older prefix match.
"""

from __future__ import annotations

from pathlib import Path

from builders.gate_readiness import acceptance_recheck, ack_recheck, readiness
from finishup.cli.closure_gate import (
    ACCEPTANCE_RECHECK_ITEM,
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
    host: str | None = None,
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
        host=host,
    )


def test_the_reread_persists_across_gate_invocations_and_returns_after_a_material_delta(
    tmp_path: Path,
) -> None:
    invite = acceptance_recheck()
    first = _decide("10", "3", frozenset(), host="cursor")
    assert first is not None
    assert ACCEPTANCE_RECHECK_ITEM in first.items
    assert "until the work, its verification, or the review mode changes" in first.text
    assert first.blocker_keys == (f"{invite.key}@10@m3",)
    assert record_closure_gate_delivered(
        _SESSION,
        f"10:{_DIGEST}",
        blocker_keys=first.blocker_keys,
        _state=tmp_path,
    )

    # A later invocation reads the file. It does not share the first gate object.
    remembered = closure_gate_reasked_blockers(_SESSION, _state=tmp_path)
    assert remembered == frozenset({f"{invite.key}@10@m3"})
    assert _decide("14", "3", remembered) is None
    assert _decide("20", "3", closure_gate_reasked_blockers(_SESSION, _state=tmp_path)) is None

    again = _decide("21", "7", closure_gate_reasked_blockers(_SESSION, _state=tmp_path))
    assert again is not None
    assert ACCEPTANCE_RECHECK_ITEM in again.items
    assert again.blocker_keys == (f"{invite.key}@21@m7",)

    # The invite frontier is the decimal before ``@m``, so an acknowledgement after it is not
    # challenged, and one published before it still is.
    answered = _decide(
        "22",
        "3",
        remembered,
        rechecks=(invite, ack_recheck(since=11)),
    )
    assert answered is None
    earlier = _decide(
        "22",
        "3",
        remembered,
        rechecks=(invite, ack_recheck(since=9)),
    )
    assert earlier is not None
    assert ACCEPTANCE_RECHECK_ITEM not in earlier.items
    assert earlier.items == (ACKNOWLEDGEMENT_RECHECK_ITEM,)

    legacy = frozenset({f"{invite.key}@10"})
    asked = _decide("22", "3", legacy)
    assert asked is not None
    assert ACCEPTANCE_RECHECK_ITEM in asked.items

    omitted = _decide("30", None, legacy)
    assert omitted is None
    stored = _decide("30", None, frozenset({f"{invite.key}@4@m1"}))
    assert stored is None
