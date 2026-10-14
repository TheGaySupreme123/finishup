"""The Stop gate asks the re-checks readiness announces, not riders on other tokens (tb4n3 RC-8).

Provenance: tb4n3 (28 real Codex runs, build 26e9cecf), issue #1031. The gate used to carry the
A-12 acceptance re-read, the acknowledgement re-check and the premise ask as riders on other
tokens: the acceptance sentence was missing in about 70% of the attempts (a gate only fired when
another token was present), the status directive said "Nothing further to do" while a gate then
re-challenged an acknowledgement its own acceptance sentence had invited (ks S, cargo D), and in
formal-crypto S every Stop after the first was an active Stop, so the "never withdraw a working
deliverable" text of ``declared_output_emptied`` was never shown to the agent that emptied its
solver.

The two repros moved here from the verification scratch are
``test_c5_acceptance_reread_is_asked_without_another_gate_token`` (family C) and
``test_b2_stop_gate_continues_a_readiness_that_says_nothing_further_to_do`` (family B). Both
failed on 26e9cecf. They now state the contract in terms of the list status announces:
``closure_readiness.rechecks``.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from builders.gate_readiness import (
    acceptance_key,
    acceptance_recheck,
    ack_recheck,
    blocker_recheck,
    obligation_id,
    premise_recheck,
    readiness,
)
from finishup.cli import closure_gate as gate_module
from finishup.cli.closure_gate import (
    ACCEPTANCE_RECHECK_ITEM,
    ACKNOWLEDGEMENT_RECHECK_ITEM,
    PREMISE_RECHECK_ITEM,
    closure_gate_from_readiness,
)
from finishup.kernel.task_facts import (
    DECLARED_OUTPUT_EMPTIED_GAP,
    DECLARED_OUTPUT_REMOVED_GAP,
    STOP_GATE_TOKENS,
)

_DIGEST = "sha256:" + "d" * 64
_OBL = "obl_da7fcee1-979b-4a5c-84cc-daf668869d31"
_FND = "fnd_28afe22a-9741-4830-b4eb-84af6faf0262"
_AWAITING = "finding_rejection_awaiting_ruling"


def _gate(
    value: object,
    *,
    sequence: str = "442",
    reasked: frozenset[str] = frozenset(),
    active: bool = False,
    pending: bool = False,
) -> Any:
    return closure_gate_from_readiness(
        value,
        frontier_sequence=sequence,
        frontier_digest=_DIGEST,
        observation_pending=pending,
        reasked_blockers=reasked,
        active_stop=active,
    )


# --- moved repros -----------------------------------------------------------------------------


def test_c5_acceptance_reread_is_asked_without_another_gate_token() -> None:
    """FN on 26e9cecf: everything resolved, no Stop-gate token -> no gate at all, so the A-12
    acceptance re-read was never asked. In cargo D it was delivered only because the false
    ``declared_output_emptied`` token fired the gate. Status announces the re-read now, so the
    gate asks it with no other token present."""

    announced = readiness(
        "ready_with_limitations",
        (),
        rechecks=(acceptance_recheck(),),
        acknowledged_obligation_count="0",
        receipt_blocking_finding_count="0",
    )
    gate = _gate(announced)
    assert gate is not None
    assert "acceptance_criteria" in gate.text
    assert gate.items == (ACCEPTANCE_RECHECK_ITEM,)
    # The key carries the frontier of the invite so an acknowledgement answering it is recognised.
    assert gate.blocker_keys == (f"{acceptance_recheck().key}@442",)
    # The same state with nothing announced is not gated: the re-read is a readiness item.
    silent = readiness("ready_with_limitations", (), rechecks=())
    assert _gate(silent) is None


def test_c5b_the_acceptance_reread_also_rides_beside_a_real_token() -> None:
    """Control: the re-read is asked in the same gate as an unrelated token such as the closing
    review, so one Stop delivers both."""

    announced = readiness(
        "action_required", ("closing_review_required",), rechecks=(acceptance_recheck(),)
    )
    gate = _gate(announced)
    assert gate is not None
    assert gate.items == ("closing_review_required", ACCEPTANCE_RECHECK_ITEM)
    assert "acceptance_criteria" in gate.text
    assert "`final_review: true`" in gate.text


def test_b2_stop_gate_continues_a_readiness_that_says_nothing_further_to_do() -> None:
    """ks S / cargo D / lake / vpp S on 26e9cecf: status said "Nothing further to do" and an
    active Stop then re-challenged the acknowledged obligation. A gate for an item status did not
    announce is never produced; the same state with the re-check announced is."""

    state = {
        "state": "ready_with_limitations",
        "agent_actionable": (),
        "standing_limitations": ("content_unselected",),
        "acknowledged_not_done": (_OBL,),
        "acknowledged_not_done_count": "1",
        "acknowledged_obligation_count": "1",
        "blocked_obligations": (),
        "open_obligation_count": "0",
        "receipt_blocking_finding_count": "0",
    }
    for active in (True, False):
        silent = SimpleNamespace(rechecks=(), **state)
        assert _gate(silent, sequence="758", active=active) is None
        # A readiness older than the list announces nothing either.
        assert _gate(SimpleNamespace(**state), sequence="758", active=active) is None
    # Control (pretrain S): when status does announce the acknowledgement re-check it is asked,
    # on an active Stop too.
    announced = SimpleNamespace(rechecks=(ack_recheck(_OBL),), **state)
    for active in (True, False):
        gate = _gate(announced, sequence="758", active=active)
        assert gate is not None
        assert gate.items == (ACKNOWLEDGEMENT_RECHECK_ITEM,)
        assert _OBL in gate.text


# --- invite-then-challenge --------------------------------------------------------------------


def test_an_acknowledgement_after_the_acceptance_invite_is_not_challenged() -> None:
    """cargo D: the acceptance sentence told the agent to republish an unmet obligation as
    ``acknowledged_not_done``; the next gate then re-asked that very acknowledgement."""

    invite = acceptance_recheck()
    first = _gate(readiness("ready_with_limitations", (), rechecks=(invite,)), sequence="400")
    assert first is not None
    (invite_key,) = first.blocker_keys
    assert invite_key == f"{invite.key}@400"
    memory = frozenset({invite_key})
    answered = readiness(
        "ready_with_limitations", (), rechecks=(invite, ack_recheck(_OBL, since=410))
    )
    assert _gate(answered, sequence="415", reasked=memory) is None
    assert _gate(answered, sequence="415", reasked=memory, active=True) is None
    # An acknowledgement that predates the invite was not an answer to it: asked once.
    older = readiness("ready_with_limitations", (), rechecks=(invite, ack_recheck(_OBL, since=300)))
    again = _gate(older, sequence="415", reasked=memory)
    assert again is not None
    assert again.items == (ACKNOWLEDGEMENT_RECHECK_ITEM,)
    # With no invite delivered, every acknowledgement is asked, whenever it was published.
    no_invite = readiness("ready_with_limitations", (), rechecks=(ack_recheck(_OBL, since=410),))
    assert _gate(no_invite, sequence="415") is not None


def test_the_earliest_invite_decides_which_acknowledgement_answered_it() -> None:
    """A second invite (the resolved set changed) does not turn the answer to the first into a
    challenge: the acknowledgement is later than the earliest invite."""

    memory = frozenset({f"{acceptance_key(['obl_a'])}@100", f"{acceptance_key(['obl_b'])}@500"})
    answered = readiness("ready_with_limitations", (), rechecks=(ack_recheck(_OBL, since=120),))
    assert _gate(answered, sequence="600", reasked=memory) is None


# --- once per key -----------------------------------------------------------------------------


def test_the_acceptance_reread_is_asked_once_per_resolved_set() -> None:
    invite = acceptance_recheck()
    gate = _gate(readiness("ready_with_limitations", (), rechecks=(invite,)), sequence="10")
    assert gate is not None
    memory = frozenset(gate.blocker_keys)
    for sequence in ("11", "99"):
        assert (
            _gate(
                readiness("ready_with_limitations", (), rechecks=(invite,)),
                sequence=sequence,
                reasked=memory,
            )
            is None
        )
    # A different resolved set is a new re-read.
    changed = acceptance_recheck((obligation_id(200), obligation_id(201), obligation_id(202)))
    assert changed.key != invite.key
    assert (
        _gate(
            readiness("ready_with_limitations", (), rechecks=(changed,)),
            sequence="99",
            reasked=memory,
        )
        is not None
    )


def test_the_acceptance_reread_is_not_offered_beside_open_obligations_and_stays_unasked() -> None:
    announced = readiness(
        "action_required", ("obligations_open",), rechecks=(acceptance_recheck(),)
    )
    gate = _gate(announced)
    assert gate is not None
    assert gate.items == ("obligations_open",)
    assert "acceptance_criteria" not in gate.text
    assert gate.blocker_keys == ()  # not remembered: asked at a later Stop


def test_the_acceptance_sentence_has_a_verification_limit_branch_that_is_not_a_retreat() -> None:
    text = gate_module._ACCEPTANCE_TEXT  # pyright: ignore[reportPrivateUsage]
    assert "acknowledged_not_done" in text
    assert "`finishup-verification-limit:<obligation id>`" in text
    assert "outside this environment" in text
    # The branch is for what cannot be verified here; "I could not find it" does not qualify.
    assert "you did the work" in text


# --- rejected finding awaiting a ruling (ks S) ------------------------------------------------


def _awaiting(**extra: Any) -> Any:
    return readiness(
        "action_required",
        (_AWAITING,),
        finding_counts=SimpleNamespace(
            to_do="1", awaiting_ruling="1", unmet="0", disclosed="0", self_verify_eligible="0"
        ),
        **extra,
    )


def test_awaiting_ruling_is_a_stop_gate_token() -> None:
    assert _AWAITING in STOP_GATE_TOKENS
    assert _AWAITING in gate_module._GATE_TOKENS  # pyright: ignore[reportPrivateUsage]


def test_awaiting_ruling_sends_the_agent_to_the_closing_review_and_never_to_acknowledge() -> None:
    gate = _gate(_awaiting())
    assert gate is not None
    assert gate.items == (_AWAITING,)
    assert "1 finding(s) you rejected await a reviewer ruling" in gate.text
    assert "`check` with `final_review: true`" in gate.text
    assert "do not acknowledge a finding you dispute" in gate.text
    # No acknowledgement is offered anywhere in the text.
    assert "acknowledged_not_done" not in gate.text
    assert "republish" not in gate.text


def test_the_acceptance_invitation_never_rides_beside_a_rejected_finding() -> None:
    announced = _awaiting(rechecks=(acceptance_recheck(),))
    gate = _gate(announced)
    assert gate is not None
    assert "acceptance_criteria" not in gate.text
    assert "acknowledged_not_done" not in gate.text
    assert ACCEPTANCE_RECHECK_ITEM not in gate.items
    assert gate.blocker_keys == ()


def test_receipt_findings_unresolved_counts_agent_work_only() -> None:
    both = readiness(
        "action_required",
        ("receipt_findings_unresolved", _AWAITING),
        finding_counts=SimpleNamespace(
            to_do="3", awaiting_ruling="1", unmet="0", disclosed="0", self_verify_eligible="2"
        ),
        receipt_blocking_finding_count="3",
    )
    gate = _gate(both)
    assert gate is not None
    assert "2 receipt-blocking finding(s) not repaired" in gate.text
    assert "1 finding(s) you rejected await a reviewer ruling" in gate.text
    # The legacy count is used only when the service sent no counts.
    legacy = readiness(
        "action_required", ("receipt_findings_unresolved",), receipt_blocking_finding_count="3"
    )
    legacy_gate = _gate(legacy)
    assert legacy_gate is not None
    assert "3 receipt-blocking finding(s) not repaired" in legacy_gate.text


@pytest.mark.parametrize(
    ("eligible", "offered"), [("0", False), ("1", True), ("4", True), (None, True)]
)
def test_self_verified_is_offered_only_when_a_finding_is_eligible(
    eligible: str | None, offered: bool
) -> None:
    counts: dict[str, Any] = (
        {}
        if eligible is None
        else {
            "finding_counts": SimpleNamespace(
                to_do="2",
                awaiting_ruling="0",
                unmet="0",
                disclosed="0",
                self_verify_eligible=eligible,
            )
        }
    )
    gate = _gate(readiness("action_required", ("receipt_findings_unresolved",), **counts))
    assert gate is not None
    assert ("respond `self_verified`" in gate.text) is offered
    if not offered:
        assert "`self_verified` is not accepted for these findings" in gate.text
        assert (
            "Respond `acknowledged_not_done` only if you truly cannot or will not do it"
            in gate.text
        )


# --- withdrawn deliverable bypasses the active-Stop suppression (formal-crypto S) -------------


def _lineage(code: str, *, basis: str | None = "verified", obligation: str = _OBL) -> Any:
    return SimpleNamespace(
        code=code,
        rule="deliverable_path_history",
        state="emptied" if code == DECLARED_OUTPUT_EMPTIED_GAP else "removed",
        obligation_id=obligation,
        item_index="0",
        basis=basis,
    )


def _emptied(*, lineage: tuple[Any, ...] | None = None, **extra: Any) -> Any:
    if lineage is None:
        lineage = (_lineage(DECLARED_OUTPUT_EMPTIED_GAP),)
    return readiness(
        "action_required",
        (DECLARED_OUTPUT_EMPTIED_GAP,),
        fact_lineage=lineage,
        open_obligation_count="0",
        receipt_blocking_finding_count="0",
        **extra,
    )


def test_an_emptied_deliverable_is_voiced_on_an_active_stop() -> None:
    gate = _gate(_emptied(), active=True)
    assert gate is not None
    assert gate.items == (DECLARED_OUTPUT_EMPTIED_GAP,)
    assert (
        "You withdrew a deliverable that passed your verification run; an empty file scores as no solution;"
        " restore it and disclose its limits."
    ) in gate.text
    # Rule and obligation id, never a path.
    assert "rule deliverable_path_history" in gate.text
    assert _OBL in gate.text
    assert "/" not in gate.text
    assert len(gate.text) <= 2000
    (key,) = gate.blocker_keys
    assert key.startswith("emptied:") and len(key) == len("emptied:") + 8


def test_an_emptied_deliverable_is_voiced_once_per_key() -> None:
    first = _gate(_emptied(), active=True)
    assert first is not None
    memory = frozenset(first.blocker_keys)
    assert _gate(_emptied(), active=True, reasked=memory) is None
    # A different withdrawn deliverable is a new key.
    other = _gate(
        _emptied(lineage=(_lineage(DECLARED_OUTPUT_EMPTIED_GAP, obligation=obligation_id(7)),)),
        active=True,
        reasked=memory,
    )
    assert other is not None
    assert other.blocker_keys != first.blocker_keys


def test_a_first_stop_gate_that_voiced_it_records_the_key_for_the_active_stops() -> None:
    first = _gate(_emptied())
    assert first is not None
    assert first.items == (DECLARED_OUTPUT_EMPTIED_GAP,)
    assert any(key.startswith("emptied:") for key in first.blocker_keys)
    assert _gate(_emptied(), active=True, reasked=frozenset(first.blocker_keys)) is None


def test_a_deliverable_not_known_to_have_passed_is_not_said_to_have_passed() -> None:
    held = _gate(_emptied(lineage=(_lineage(DECLARED_OUTPUT_EMPTIED_GAP, basis="delivered"),)))
    assert held is not None
    assert (
        "You withdrew a deliverable that held content; an empty file scores as no solution"
        in held.text
    )
    assert "passed your verification run" not in held.text
    bare = _gate(_emptied(lineage=()), active=True)
    assert bare is not None
    assert "held content" in bare.text
    assert bare.blocker_keys[0].startswith("emptied:")


def test_a_removed_deliverable_is_voiced_on_an_active_stop_as_a_missing_file() -> None:
    removed = readiness(
        "action_required",
        (DECLARED_OUTPUT_REMOVED_GAP,),
        fact_lineage=(_lineage(DECLARED_OUTPUT_REMOVED_GAP),),
    )
    gate = _gate(removed, active=True)
    assert gate is not None
    assert gate.items == (DECLARED_OUTPUT_REMOVED_GAP,)
    assert "a missing file scores as no solution" in gate.text


def test_the_active_stop_still_ignores_every_ordinary_item() -> None:
    ordinary = readiness(
        "action_required",
        ("obligations_open", "receipt_findings_unresolved", "closing_review_required", _AWAITING),
    )
    assert _gate(ordinary, active=True) is None
    mixed = readiness(
        "action_required",
        ("obligations_open", DECLARED_OUTPUT_EMPTIED_GAP),
        fact_lineage=(_lineage(DECLARED_OUTPUT_EMPTIED_GAP),),
    )
    gate = _gate(mixed, active=True)
    assert gate is not None
    assert gate.items == (DECLARED_OUTPUT_EMPTIED_GAP,)
    assert "open obligation" not in gate.text


def test_the_acceptance_invitation_never_rides_beside_a_withdrawn_deliverable() -> None:
    gate = _gate(_emptied(rechecks=(acceptance_recheck(),)))
    assert gate is not None
    assert "acceptance_criteria" not in gate.text
    assert gate.blocker_keys[0].startswith("emptied:")
    assert not any(key.startswith("accept:") for key in gate.blocker_keys)


# --- the working deliverable survives the re-checks (formal-crypto S; pretrain S control) ------


def test_premise_and_acknowledgement_texts_keep_the_working_deliverable() -> None:
    keep = (
        "If you cannot finish it, keep the working deliverable; acknowledgement never requires"
        " withdrawing or emptying it."
    )
    assert keep in gate_module._PREMISE_TEXT  # pyright: ignore[reportPrivateUsage]
    keys = (f"ack:{_OBL}",)
    for short in (False, True):
        text = gate_module._acknowledgement_text(keys, short=short)  # pyright: ignore[reportPrivateUsage]
        assert keep in text
        # The pretrain S rescue is intact: the push back to work is still the first instruction.
        assert "do that work unless it is genuinely impossible" in text.lower()
        assert text.index("genuinely impossible") < text.index("keep the working deliverable")


def test_pretrain_s_gate_still_sends_an_agent_that_gave_up_back_to_work() -> None:
    """pretrain S (tb4n3, reward 1.0): one open obligation, three acknowledged obligations and a
    premise dispute at the first Stop. The rescue is the combination; all of it is still there."""

    state = readiness(
        "action_required",
        ("obligations_open",),
        rechecks=(
            premise_recheck(3),
            *(ack_recheck(obligation_id(index)) for index in (1, 2, 3)),
        ),
        open_obligation_count="1",
    )
    gate = _gate(state, sequence="576")
    assert gate is not None
    assert PREMISE_RECHECK_ITEM in gate.items and ACKNOWLEDGEMENT_RECHECK_ITEM in gate.items
    assert "Do that work unless it is genuinely impossible" in gate.text
    assert "Finish each open obligation" in gate.text
    assert "keep the working deliverable" in gate.text
    assert "Acknowledgement re-check (asked once)" in gate.text
    assert len(gate.text) <= 2000


def test_the_acknowledgement_and_premise_rechecks_are_asked_once_per_key() -> None:
    state = readiness(
        "ready_with_limitations", (), rechecks=(premise_recheck(2), ack_recheck(_OBL))
    )
    gate = _gate(state)
    assert gate is not None
    assert gate.items == (PREMISE_RECHECK_ITEM, ACKNOWLEDGEMENT_RECHECK_ITEM)
    assert gate.blocker_keys == ("premise:2", f"ack:{_OBL}")
    memory = frozenset(gate.blocker_keys)
    assert _gate(state, reasked=memory) is None
    # A premise re-check never continues a Stop the host already continued.
    active = _gate(state, active=True)
    assert active is not None
    assert active.items == (ACKNOWLEDGEMENT_RECHECK_ITEM,)


def test_a_blocker_keeps_its_historical_memory_key() -> None:
    gate = _gate(
        readiness("ready_with_limitations", (), rechecks=(blocker_recheck(_OBL, "consent"),))
    )
    assert gate is not None
    assert gate.blocker_keys == (f"{_OBL}:consent",)
    assert (
        _gate(
            readiness("ready_with_limitations", (), rechecks=(blocker_recheck(_OBL, "consent"),)),
            reasked=frozenset({f"{_OBL}:consent"}),
        )
        is None
    )


@pytest.mark.parametrize("active", [False, True])
@pytest.mark.parametrize("state", ["unknown", None, "action_required_typo"])
def test_an_unreadable_state_never_gates(state: object, active: bool) -> None:
    announced = readiness(str(state), (), rechecks=(acceptance_recheck(),))
    announced.state = state
    assert _gate(announced, active=active) is None


# --- closure_prepare reads the same list ------------------------------------------------------


def test_closure_prepare_names_the_rechecks_the_gate_will_ask() -> None:
    from finishup.domain.closure import recheck_note

    announced = readiness(
        "ready_with_limitations",
        (),
        rechecks=(acceptance_recheck(), ack_recheck(_OBL), ack_recheck(obligation_id(101))),
    )
    note = recheck_note(announced)
    assert note is not None
    assert note.startswith("At Stop you will be asked once to re-read: ")
    assert "the acceptance criteria of your resolved obligations" in note
    assert "obligations you recorded as not done" in note
    assert note.count("obligations you recorded as not done") == 1
    # What the note names is exactly what the gate asks.
    gate = _gate(announced)
    assert gate is not None
    assert gate.items == (ACKNOWLEDGEMENT_RECHECK_ITEM, ACCEPTANCE_RECHECK_ITEM)
    assert recheck_note(readiness("ready", (), rechecks=())) is None
    assert recheck_note(readiness("ready", (), rechecks=None)) is None


def test_the_awaiting_ruling_text_names_the_finding_and_the_frontier_of_the_rejection() -> None:
    """Owner decision 10: a derived item says why it fired (rule, ids, frontier)."""

    gate = _gate(
        _awaiting(
            awaiting_ruling_findings=(SimpleNamespace(finding_id=_FND, since_frontier="252"),)
        )
    )
    assert gate is not None
    assert f"Why: no check has ruled on {_FND} (rejected at frontier 252)." in gate.text
    assert f"Rule {_AWAITING}." in gate.text
    # Malformed lineage entries are skipped, never rendered.
    odd = _gate(
        _awaiting(
            awaiting_ruling_findings=(
                SimpleNamespace(finding_id="not-an-id", since_frontier="1"),
                SimpleNamespace(finding_id=None, since_frontier="1"),
            )
        )
    )
    assert odd is not None
    assert _FND not in odd.text
    # Without named findings the rule and where to read them are still said.
    assert "Why: you answered a finding `rejected` and no check has ruled on it since" in odd.text
    assert f"Rule {_AWAITING}." in odd.text
    bare = _gate(_awaiting())
    assert bare is not None
    assert "status view=findings lists them" in bare.text


# --- Codex review round 1 (W2-C) ----------------------------------------------------------------


def test_the_acceptance_invitation_is_withheld_on_an_active_stop_beside_unvoiced_items() -> None:
    """An active Stop computes no ordinary items, but a rejected finding awaiting a ruling, open
    obligations or a withdrawn deliverable that is present still keep the invitation to
    acknowledge unasked (and unremembered): Codex round 1, finding 1."""

    for token in (_AWAITING, "obligations_open"):
        announced = readiness("action_required", (token,), rechecks=(acceptance_recheck(),))
        assert _gate(announced, active=True) is None, token
    # A withdrawn deliverable already voiced still excludes it.
    voiced = _emptied(rechecks=(acceptance_recheck(),))
    first = _gate(voiced, active=True)
    assert first is not None
    assert first.items == (DECLARED_OUTPUT_EMPTIED_GAP,)
    assert _gate(voiced, active=True, reasked=frozenset(first.blocker_keys)) is None
    # With none of them present the same invitation is asked.
    clear = readiness(
        "action_required", ("closing_review_required",), rechecks=(acceptance_recheck(),)
    )
    gate = _gate(clear, active=True)
    assert gate is not None
    assert gate.items == (ACCEPTANCE_RECHECK_ITEM,)


def test_the_earliest_acceptance_invite_survives_the_memory_bound(tmp_path: Any) -> None:
    """Codex round 1, finding 3: the invite's frontier is the only memory of which acknowledgement
    answered it; 64 later keys must not evict it."""

    invite = acceptance_recheck()
    first = _gate(readiness("ready_with_limitations", (), rechecks=(invite,)), sequence="400")
    assert first is not None
    assert gate_module.record_closure_gate_delivered(
        "ses_a", first.identity, blocker_keys=first.blocker_keys, _state=tmp_path
    )
    noise = tuple(f"obl_{index:04d}:consent" for index in range(80))
    assert gate_module.record_closure_gate_delivered(
        "ses_a", "9:x", blocker_keys=noise, _state=tmp_path
    )
    memory = gate_module.closure_gate_reasked_blockers("ses_a", _state=tmp_path)
    assert len(memory) <= 64
    assert first.blocker_keys[0] in memory
    answered = readiness(
        "ready_with_limitations", (), rechecks=(invite, ack_recheck(_OBL, since=410))
    )
    assert _gate(answered, sequence="500", reasked=memory) is None
    # Later invites are bounded too: trimming always keeps the earliest invite of the session.
    for index in range(40):
        key = f"{acceptance_key([obligation_id(300 + index)])}@{500 + index}"
        assert gate_module.record_closure_gate_delivered(
            "ses_b", "1:x", blocker_keys=(key, *noise[index * 2 : index * 2 + 2]), _state=tmp_path
        )
    kept = gate_module.closure_gate_reasked_blockers("ses_b", _state=tmp_path)
    assert len(kept) <= 64
    assert f"{acceptance_key([obligation_id(300)])}@500" in kept
    assert f"{acceptance_key([obligation_id(339)])}@539" in kept


_PREDICTION = SimpleNamespace(
    conclusion="insufficient_coverage",
    reasons=(
        SimpleNamespace(code="obligations_acknowledged", rule="R3", count="2", refs=()),
        SimpleNamespace(code="findings_disclosed", rule="R4", count="1", refs=()),
    ),
)


def test_the_gate_ends_with_the_predicted_receipt_conclusion_and_drops_it_first() -> None:
    """DESIGN_RC3 3.4(7) and owner decision Q1: the same prediction every surface prints, as the
    lowest-priority optional sentence; Codex round 1, finding 5."""

    announced = readiness(
        "ready_with_limitations",
        (),
        rechecks=(acceptance_recheck(),),
        predicted_receipt=_PREDICTION,
    )
    gate = _gate(announced)
    assert gate is not None
    assert gate.text.endswith(
        "The receipt will read insufficient_coverage: 2 acknowledged obligation(s), 1 disclosed"
        " finding(s)."
    )
    assert "acceptance_criteria" in gate.text
    # Work remaining reads as a counterfactual, never as a promise.
    work = readiness(
        "action_required",
        ("closing_review_required",),
        predicted_receipt=SimpleNamespace(conclusion="unresolved_findings_remain", reasons=()),
    )
    work_gate = _gate(work)
    assert work_gate is not None
    assert work_gate.text.endswith("A receipt requested now would read unresolved_findings_remain.")
    # It never makes a gate fire, and a service without it adds nothing.
    assert _gate(readiness("ready_with_limitations", (), predicted_receipt=_PREDICTION)) is None
    assert (
        "will read"
        not in _gate(readiness("ready_with_limitations", (), rechecks=(acceptance_recheck(),))).text
    )  # type: ignore[union-attr]


def test_the_prediction_is_the_first_sentence_dropped_under_the_host_bound() -> None:
    """With every token and re-check the 2,000-character bound is full: the prediction yields
    before the acceptance sentence, the premise ask or any re-check does."""

    crowded = readiness(
        "action_required",
        tuple(gate_module._GATE_TOKENS),  # pyright: ignore[reportPrivateUsage]
        rechecks=(
            *(blocker_recheck(obligation_id(index)) for index in range(3)),
            premise_recheck(3),
            *(ack_recheck(obligation_id(100 + index)) for index in range(3)),
            acceptance_recheck(),
        ),
        predicted_receipt=_PREDICTION,
        limitation_refs_required=tuple(
            f"res_97700000-0000-4000-8000-{index:012d}" for index in range(5)
        ),
        limitation_refs_required_count="40",
    )
    gate = _gate(crowded)
    assert gate is not None
    assert len(gate.text) <= 2000
    assert "will read" not in gate.text and "would read" not in gate.text
    assert gate_module._CLOSE_TEXT in gate.text  # pyright: ignore[reportPrivateUsage]
    # Yielding the tail changes nothing else: the same readiness without a prediction composes
    # to the same gate (nothing else was dropped to make room for it).
    crowded.predicted_receipt = None
    bare = _gate(crowded)
    assert bare is not None
    assert (bare.text, bare.items, bare.blocker_keys) == (gate.text, gate.items, gate.blocker_keys)


@pytest.mark.parametrize("tokens_name", ["none", "findings", "obligations", "all"])
@pytest.mark.parametrize("blockers", [0, 1, 3])
@pytest.mark.parametrize("acknowledgements", [0, 1, 3])
@pytest.mark.parametrize("premise", [False, True])
@pytest.mark.parametrize("acceptance", [False, True])
def test_the_prediction_never_changes_what_else_the_gate_says(
    tokens_name: str, blockers: int, acknowledgements: int, premise: bool, acceptance: bool
) -> None:
    """Codex round 2: the predicted conclusion is the first sentence dropped. Whatever the mix,
    the gate with a prediction is the gate without one, plus at most that one tail sentence: it is
    never squeezed in beside a re-check or instruction that was dropped or shortened."""

    tokens = {
        "none": (),
        "findings": ("receipt_findings_unresolved",),
        "obligations": ("obligations_open", "receipt_findings_unresolved"),
        "all": tuple(gate_module._GATE_TOKENS),  # pyright: ignore[reportPrivateUsage]
    }[tokens_name]
    announced = (
        *(blocker_recheck(obligation_id(index)) for index in range(blockers)),
        *(ack_recheck(obligation_id(100 + index)) for index in range(acknowledgements)),
        *((premise_recheck(3),) if premise else ()),
        *((acceptance_recheck(),) if acceptance else ()),
    )
    if not tokens and not announced:
        return

    def build(prediction: object) -> Any:
        return readiness(
            "action_required" if tokens else "ready_with_limitations",
            tokens,
            rechecks=announced,
            predicted_receipt=prediction,
            open_obligation_count="3",
            receipt_blocking_finding_count="2",
            limitation_refs_required=tuple(
                f"res_97700000-0000-4000-8000-{index:012d}" for index in range(5)
            ),
            limitation_refs_required_count="40",
        )

    bare = _gate(build(None))
    with_tail = _gate(build(_PREDICTION))
    assert (bare is None) == (with_tail is None)
    if bare is None or with_tail is None:
        return
    assert (with_tail.items, with_tail.blocker_keys) == (bare.items, bare.blocker_keys)
    assert len(with_tail.text) <= 2000
    state = "action_required" if tokens else "ready_with_limitations"
    from finishup.protocol.readiness_text import predicted_receipt_variants

    tails = {f" {variant}" for variant in predicted_receipt_variants(_PREDICTION, state=state)}
    assert with_tail.text == bare.text or any(
        with_tail.text == bare.text + tail for tail in tails
    ), (tokens_name, blockers, acknowledgements, premise, acceptance)


def test_the_gate_never_claims_a_challenge_it_did_not_deliver() -> None:
    """Codex round 3: the unconfirmed-blocker token alone, with no re-check announced (a service
    older than the gate) and an empty memory, must not say "you were already asked"."""

    token = gate_module.BLOCKER_UNCONFIRMED_TOKEN
    legacy = _gate(readiness("action_required", (token,), rechecks=None))
    assert legacy is not None
    assert "You were already asked" not in legacy.text
    assert "same finishup-blocker line again" not in legacy.text
    silent = _gate(readiness("action_required", (token,), rechecks=()))
    assert silent is not None
    assert "You were already asked" not in silent.text
    # Announced and not yet asked: the challenge itself is delivered, not the "already" sentence.
    claimed = readiness("action_required", (token,), rechecks=(blocker_recheck(_OBL, "consent"),))
    first = _gate(claimed)
    assert first is not None
    assert "Blocker re-check (asked once)" in first.text
    assert "You were already asked" not in first.text
    # Announced and already asked: now, and only now, the text says so.
    again = _gate(claimed, reasked=frozenset(first.blocker_keys))
    assert again is not None
    assert "You were already asked about your recorded blocker" in again.text


# --- the fact-lineage sentence is the first optional sentence trimmed; the cause stays ----------


def _wire_lineage() -> Any:
    from finishup.domain.values import obligation_id as typed_obligation_id
    from finishup.kernel.fact_lineage import FactLineage, lineage_to_wire

    return lineage_to_wire(
        FactLineage(
            code=DECLARED_OUTPUT_EMPTIED_GAP,
            rule="deliverable_path_history",
            state="emptied",
            obligation_id=typed_obligation_id(_OBL),
            item_index=0,
            frontier=7,
            prior_size_bytes=15_975,
            prior_lines=310,
            now_size_bytes=0,
            now_lines=0,
            proof="earlier_check",
            basis="verified",
        )
    )


def test_the_lineage_sentence_is_present_when_the_gate_fits_and_trimmed_first_otherwise() -> None:
    from finishup.kernel.fact_lineage import lineage_from_wire, lineage_text

    wire = _wire_lineage()
    why = lineage_text(lineage_from_wire(wire))
    roomy = _gate(_emptied(lineage=(wire,)))
    assert roomy is not None and why in roomy.text

    # Beside two more announced re-checks the whole gate no longer fits 2,000 characters: the
    # lineage sentence yields first, and every token still says why it fired - the withdrawn
    # sentence names the rule and the obligation, the item clause names the cause.
    crowded = _gate(
        _emptied(
            lineage=(wire,),
            rechecks=(
                premise_recheck(1),
                ack_recheck(_OBL),
                blocker_recheck(obligation_id(2)),
            ),
        )
    )
    assert crowded is not None and len(crowded.text) <= 2_000
    assert DECLARED_OUTPUT_EMPTIED_GAP in crowded.items
    assert why not in crowded.text
    assert "You withdrew a deliverable" in crowded.text
    assert "rule deliverable_path_history" in crowded.text and _OBL in crowded.text
    assert "is now empty or truncated" in crowded.text
