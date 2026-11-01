"""#1240 D2: one batched Stop question per set of open material reviewer notes, on every host."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.unit.cli.test_closure_gate import (
    _Harness,  # pyright: ignore[reportPrivateUsage]
    _Host,  # pyright: ignore[reportPrivateUsage]
    _stop,  # pyright: ignore[reportPrivateUsage]
    _text,  # pyright: ignore[reportPrivateUsage]
)

from builders.gate_readiness import (
    ack_recheck,
    obligation_id,
    premise_recheck,
    readiness,
    recheck,
)
from finishup.cli import closure_gate as gate_module
from finishup.cli.closure_gate import (
    ADVICE_RECHECK_ITEM,
    PREMISE_RECHECK_ITEM,
    closure_gate_from_readiness,
)
from finishup.kernel.closure_verdict import advice_recheck

_DIGEST = "sha256:" + "d" * 64
_NOTE = "evt_00000000-0000-4000-8000-000000000001:2"
_DECISION = "fnd_00000000-0000-4000-8000-000000000004"


def _advice(*advice: str) -> Any:
    found = advice_recheck(advice)
    assert found is not None
    return recheck(
        found.kind, found.key, subjects=found.subjects, rule=found.rule, since=found.since_frontier
    )


def _gate(value: object, *, reasked: frozenset[str] = frozenset(), active: bool = False) -> Any:
    return closure_gate_from_readiness(
        value,
        frontier_sequence="576",
        frontier_digest=_DIGEST,
        observation_pending=False,
        reasked_blockers=reasked,
        active_stop=active,
    )


def test_the_key_names_exactly_the_open_set() -> None:
    assert advice_recheck(()) is None
    found = advice_recheck((_NOTE, _DECISION))
    assert found is not None
    assert found.kind == "advice" and found.rule == "material_advice_unanswered"
    shapes = gate_module._RECHECK_KEY_SHAPES  # pyright: ignore[reportPrivateUsage]
    assert shapes["advice"].fullmatch(found.key)
    # Order never matters; a different set is a different key.
    assert advice_recheck((_DECISION, _NOTE)) == found
    other = advice_recheck((_NOTE,))
    assert other is not None and other.key != found.key
    # Subjects are the noted check's event and the finding, never the note ordinal.
    assert found.subjects == ("evt_00000000-0000-4000-8000-000000000001", _DECISION)


def test_a_ready_task_with_open_notes_is_asked_once_per_set() -> None:
    state = readiness("ready", (), rechecks=(_advice(_NOTE, _DECISION),))
    gate = _gate(state)
    assert gate is not None
    assert gate.items == (ADVICE_RECHECK_ITEM,)
    assert gate.blocker_keys == (_advice(_NOTE, _DECISION).key,)
    assert "respond finding_id=<note id>" in gate.text
    assert "kept my choice (kept_choice, with a reason)" in gate.text
    assert "Non-blocking" in gate.text and "optional" not in gate.text
    assert _gate(state, reasked=frozenset(gate.blocker_keys)) is None
    # A changed set is asked again.
    assert (
        _gate(
            readiness("ready", (), rechecks=(_advice(_NOTE),)), reasked=frozenset(gate.blocker_keys)
        )
        is not None
    )
    # An already-continued Stop may still carry the ask (a single-turn run has no other Stop).
    active = _gate(state, active=True)
    assert active is not None and active.items == (ADVICE_RECHECK_ITEM,)


def test_a_decision_choice_is_told_the_answers_respond_admits_for_it() -> None:
    """A ``decision_needed`` finding is material advice too, but ``respond`` refuses the note
    answers (``addressed``, ``kept_choice``, ``declined``) on a finding id ("This disposition
    requires an advisory identity"), so the ask must name the finding answers as well."""

    from finishup.domain.correctness_advisories import ADVISORY_DISPOSITIONS

    gate = _gate(readiness("ready", (), rechecks=(_advice(_DECISION),)))
    assert gate is not None and gate.items == (ADVICE_RECHECK_ITEM,)
    assert "a decision choice (fnd_ id) takes acknowledged or rejected, with a reason" in gate.text
    assert not {"acknowledged", "rejected"} & ADVISORY_DISPOSITIONS


def test_the_advice_ask_never_costs_the_premise_ask_its_place() -> None:
    """pretrain S (G6: 1,994 of 2,000 characters) plus open notes: the premise ask still fits.

    The advice ask is trimmed first and not remembered, so a later Stop asks it.
    """

    advice = _advice(_NOTE)
    state = readiness(
        "action_required",
        ("obligations_open",),
        rechecks=(
            premise_recheck(3),
            *(ack_recheck(obligation_id(index)) for index in (1, 2, 3)),
            advice,
        ),
        open_obligation_count="1",
    )
    gate = _gate(state)
    assert gate is not None and len(gate.text) <= 2000
    assert PREMISE_RECHECK_ITEM in gate.items and ADVICE_RECHECK_ITEM not in gate.items
    assert "Do that work unless it is genuinely impossible" in gate.text
    assert advice.key not in gate.blocker_keys
    # A short gate carries both, premise first.
    both = _gate(readiness("ready", (), rechecks=(premise_recheck(1), advice)))
    assert both is not None
    assert both.items == (PREMISE_RECHECK_ITEM, ADVICE_RECHECK_ITEM)
    assert both.text.index("genuinely impossible") < both.text.index("Reviewer notes")


def test_closure_prepare_names_the_advice_ask() -> None:
    from finishup.domain.closure import recheck_note

    note = recheck_note(readiness("ready", (), rechecks=(_advice(_NOTE),)))
    assert note is not None and "reviewer notes with no recorded answer" in note


def test_every_host_asks_once_and_records_the_diagnostic(tmp_path: Path, host: _Host) -> None:
    session = "gate-advice"
    h = _Harness(tmp_path, host.key(session))
    h.readiness = readiness("ready", (), rechecks=(_advice(_NOTE),))
    text = _text(host, _stop(h, host, session))
    assert text.startswith("FinishUP closure gate (shown once): Reviewer notes have no recorded")
    assert h.reasons() == ["closure_gate_continued", "closure_gate_advice_asked"]
    # The ask's row names its set key (a digest of the open note set), nothing else.
    rows = [
        json.loads(line)
        for line in (h.state / "observation" / "hook-diagnostics.jsonl").read_text().splitlines()
    ]
    (asked,) = (row for row in rows if row.get("reason") == "closure_gate_advice_asked")
    assert set(asked) == {"event", "reason", "ts", "advice_set"}
    assert asked["advice_set"] == _advice(_NOTE).key
    # The same set at a later frontier is not asked again, on a fresh or a continued Stop.
    h.sequence = "6"
    assert "closure gate" not in str(_stop(h, host, session, guarded=True))
    h.sequence = "7"
    assert "closure gate" not in str(_stop(h, host, session))
    assert "closure_gate_advice_asked" not in h.reasons()[2:]


@pytest.fixture(params=["codex", "claude", "cursor"])
def host(request: pytest.FixtureRequest) -> _Host:
    return _Host(str(request.param))
