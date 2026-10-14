"""Stop-gate composition under the host bound (tb4n3 RC-2, #1025, family A5).

Before this change the gate's fallback kept ``head[:2000]`` plus whichever re-check sentence fit
and dropped every repair and close instruction, even with hundreds of characters free: a gate with
one blocker, one acknowledgement and three tokens lost its ``check`` and receipt instruction in
44 of 55 token sets. Real gates reached 1,994 characters. The cases below enumerate token sets
and check what an agent is guaranteed to be told, and that a re-check is reported as asked only
when its whole sentence is in the text.
"""

from __future__ import annotations

import itertools
from types import SimpleNamespace
from typing import Any

import pytest

from builders.gate_readiness import ack_recheck, blocker_recheck, obligation_id, premise_recheck
from finishup.cli import closure_gate as gate
from finishup.cli.closure_gate import (
    ACKNOWLEDGEMENT_RECHECK_ITEM,
    BLOCKER_RECHECK_ITEM,
    closure_gate_from_readiness,
)

_DIGEST = "sha256:" + "e" * 64
_TOKENS = gate._GATE_TOKENS  # pyright: ignore[reportPrivateUsage]
_CLOSE = gate._CLOSE_TEXT  # pyright: ignore[reportPrivateUsage]
_OBLIGATIONS = (
    gate._OBLIGATION_TEXT,  # pyright: ignore[reportPrivateUsage]
    gate._OBLIGATION_SHORT_TEXT,  # pyright: ignore[reportPrivateUsage]
)
_FINDINGS = (
    gate._FINDING_TEXT,  # pyright: ignore[reportPrivateUsage]
    gate._FINDING_SHORT_TEXT,  # pyright: ignore[reportPrivateUsage]
)
_VERIFICATION = gate._VERIFICATION_TEXT  # pyright: ignore[reportPrivateUsage]
_OBSERVATION_DEPENDENT = gate._OBSERVATION_DEPENDENT  # pyright: ignore[reportPrivateUsage]


def _readiness(
    tokens: tuple[str, ...], *, blockers: int, acknowledged: int, premise: bool, refs: int = 5
) -> Any:
    return SimpleNamespace(
        state="action_required",
        agent_actionable=tokens,
        open_obligation_count="3",
        receipt_blocking_finding_count="2",
        rechecks=(
            *(blocker_recheck(obligation_id(index)) for index in range(blockers)),
            *(ack_recheck(obligation_id(100 + index)) for index in range(acknowledged)),
            *((premise_recheck(1),) if premise else ()),
        ),
        limitation_refs_required=tuple(
            f"res_97700000-0000-4000-8000-{index:012d}" for index in range(refs)
        ),
        limitation_refs_required_count="40" if refs else "0",
    )


def _token_sets() -> list[tuple[str, ...]]:
    sets: list[tuple[str, ...]] = []
    for size in range(1, len(_TOKENS) + 1):
        if size <= 4 or size >= len(_TOKENS) - 1:
            sets.extend(itertools.combinations(_TOKENS, size))
    return sets


def test_every_present_family_and_the_close_instruction_survive_the_host_bound() -> None:
    checked = 0
    for tokens in _token_sets():
        for blockers, acknowledged, premise in itertools.product((0, 3), (0, 3), (False, True)):
            decision = closure_gate_from_readiness(
                _readiness(tokens, blockers=blockers, acknowledged=acknowledged, premise=premise),
                frontier_sequence="999999",
                frontier_digest=_DIGEST,
                observation_pending=False,
            )
            assert decision is not None
            text = decision.text
            context = (tokens, blockers, acknowledged, premise, len(text))
            assert len(text) <= 2000, context
            assert _CLOSE in text, context
            if "obligations_open" in tokens:
                assert any(sentence in text for sentence in _OBLIGATIONS), context
            if "receipt_findings_unresolved" in tokens:
                assert any(sentence in text for sentence in _FINDINGS), context
            if any(token in _OBSERVATION_DEPENDENT for token in tokens):
                assert _VERIFICATION in text, context
            # A re-check is reported as asked only when its sentence is in the text.
            assert (BLOCKER_RECHECK_ITEM in decision.items) == (
                "Blocker re-check (asked once)" in text
            ), context
            assert (ACKNOWLEDGEMENT_RECHECK_ITEM in decision.items) == (
                "Acknowledgement re-check (asked once)" in text
            ), context
            checked += 1
    assert checked > 4000


@pytest.mark.parametrize(
    ("tokens", "refs"),
    [
        # The original A5 repro, exactly: two tokens, one blocker, one acknowledgement, no
        # required limitation references.
        (("obligations_open", "receipt_findings_unresolved"), 0),
        (("obligations_open", "receipt_findings_unresolved"), 5),
        (("obligations_open", "receipt_findings_unresolved", "closing_review_required"), 5),
    ],
    ids=["a5_original", "with_limitation_refs", "with_closing_review"],
)
def test_one_blocker_plus_one_acknowledgement_keeps_the_finding_and_close_instructions(
    tokens: tuple[str, ...], refs: int
) -> None:
    """The tb4n3 A5 case: the clip kept the head and both re-checks and lost every instruction.

    The original asserted the long ``_FINDING_TEXT``; the composer correctly states the finding
    instruction in a shorter variant when the re-checks leave less room, so the contract is that
    the close instruction and a finding instruction (either variant) are both present."""

    decision = closure_gate_from_readiness(
        _readiness(tokens, blockers=1, acknowledged=1, premise=False, refs=refs),
        frontier_sequence="412",
        frontier_digest=_DIGEST,
        observation_pending=False,
    )
    assert decision is not None
    assert len(decision.text) <= 2000
    assert _CLOSE in decision.text
    assert any(sentence in decision.text for sentence in _FINDINGS)
    assert any(sentence in decision.text for sentence in _OBLIGATIONS)
    assert BLOCKER_RECHECK_ITEM in decision.items
    assert ACKNOWLEDGEMENT_RECHECK_ITEM in decision.items


def test_a_re_check_that_cannot_fit_is_not_remembered_as_asked() -> None:
    """With every token and many blockers the long sentences drop, never the instruction."""

    decision = closure_gate_from_readiness(
        _readiness(_TOKENS, blockers=99, acknowledged=3, premise=True),
        frontier_sequence="999999",
        frontier_digest=_DIGEST,
        observation_pending=False,
    )
    assert decision is not None
    assert len(decision.text) <= 2000
    assert _CLOSE in decision.text
    asked = BLOCKER_RECHECK_ITEM in decision.items
    assert asked == ("Blocker re-check (asked once)" in decision.text)
    # Every token set carries a withdrawn-deliverable token, which records its own ``emptied:``
    # key; the re-check keys are the others.
    recheck_keys = tuple(key for key in decision.blocker_keys if not key.startswith("emptied:"))
    assert bool(recheck_keys) == (
        asked or ACKNOWLEDGEMENT_RECHECK_ITEM in decision.items or "premise" in str(decision.items)
    )
    assert any(key.startswith("emptied:") for key in decision.blocker_keys)
