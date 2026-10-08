"""Stop-gate wording against the gate texts tb4n1 agents actually received (F1, #984, #985).

In tb4n1, 38 of 40 gate firings were for receipt-blocking findings the agent could not clear
because of Yoetz's own limits, and the old text offered `yoetz-blocker` as the exit; 35 firings
were answered with a blocker. The cases below are the "Remaining:" lines the agents received
(rollout `hook_prompt` texts, wheel 91e57aaf). For the readiness those attempts had, the new text
must push repair or self-verification first, name `self_verified`, keep `acknowledged_not_done`
as the last resort, and offer the blocker sentence only when obligations are open.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Any

import pytest

from yoetz.cli import closure_gate as gate_module
from yoetz.cli.closure_gate import closure_gate_from_readiness

_DIGEST = "sha256:" + "e" * 64

# Verbatim from cad-model semantic (rollout hook_prompt, ledger frontier 465).
_OLD_CAD_MODEL_TEXT = (
    "Yoetz closure gate (shown once for ledger frontier 465): closure still requires action"
    " before you stop. Remaining: 2 receipt-blocking finding(s) not repaired; the closing review"
    " has not run since your last change: run `check` with `final_review: true` (a recorded"
    " blocker does not waive it). Finish the work: run each planned verification after your last"
    " edit (or correct the requested command to the one you run), write every requested output"
    " at its requested path (status view=obligations names them; an inconsistent input is not a"
    " reason to omit one, write a best-effort artifact and disclose the assumption), repair the"
    " receipt-blocking findings, then check and request the receipt. Stop without that only for a"
    " blocker outside your control (authority, consent, credentials, a dependency you cannot"
    " obtain): publish decision_recorded with affected_obligation_ids and the statement line"
    " yoetz-blocker:<authority|consent|credential|dependency_unavailable>, then say so in your"
    " final answer. Data the task says is recoverable is not such a blocker. (Hook observations"
    " were still draining; observed-run facts were not used.)"
)

# (trial, frontier, the "Remaining:" line the agent received), verbatim from tb4n1 rollouts.
_FINDINGS_ONLY = (
    (
        "cad-model__semantic",
        "465",
        _OLD_CAD_MODEL_TEXT.split("Remaining: ")[1].split(". Finish")[0],
    ),
    ("freecad-spring-clip__semantic", "258", "1 receipt-blocking finding(s) not repaired"),
    ("rs-archive-clone__deterministic", "721", "3 receipt-blocking finding(s) not repaired"),
    ("formal-crypto__semantic", "913", "5 receipt-blocking finding(s) not repaired"),
    ("interleaved-vigenere__semantic", "553", "1 receipt-blocking finding(s) not repaired"),
    ("retro-console-soc__semantic", "1002", "1 receipt-blocking finding(s) not repaired"),
    ("vpp-loss-divergence__semantic", "435", "4 receipt-blocking finding(s) not repaired"),
)
_WITH_OBLIGATIONS = (
    ("pretrain-shard-corruption__deterministic", "471", "2 open obligation(s)"),
    (
        "pretrain-shard-corruption__semantic",
        "960",
        "4 open obligation(s); 10 receipt-blocking finding(s) not repaired",
    ),
    (
        "payments-pipeline-fix__semantic",
        "1153",
        "1 open obligation(s); 7 receipt-blocking finding(s) not repaired; the closing review has"
        " not run since your last change: run `check` with `final_review: true` (a recorded"
        " blocker does not waive it)",
    ),
)


def _readiness_from_remaining(remaining: str) -> Any:
    """Rebuild the readiness that produced one received "Remaining:" line."""

    actionable: list[str] = []
    open_count = blocking = "0"
    if match := re.search(r"(\d+) open obligation\(s\)", remaining):
        actionable.append("obligations_open")
        open_count = match.group(1)
    if match := re.search(r"(\d+) receipt-blocking finding\(s\)", remaining):
        actionable.append("receipt_findings_unresolved")
        blocking = match.group(1)
    if "closing review has not run" in remaining:
        actionable.append("closing_review_required")
    assert actionable, remaining
    return SimpleNamespace(
        state="action_required",
        agent_actionable=tuple(actionable),
        open_obligation_count=open_count,
        receipt_blocking_finding_count=blocking,
        blocked_obligations=(),
    )


def _text(frontier: str, remaining: str, *, pending: bool = True) -> str:
    gate = closure_gate_from_readiness(
        _readiness_from_remaining(remaining),
        frontier_sequence=frontier,
        frontier_digest=_DIGEST,
        # 39 of the 40 tb4n1 gates decided while observations were still draining.
        observation_pending=pending,
    )
    assert gate is not None
    return gate.text


def test_the_old_text_invited_a_blocker_for_findings_only() -> None:
    """The regression being fixed: a findings-only gate advertised the blocker exit."""

    assert "yoetz-blocker:<" in _OLD_CAD_MODEL_TEXT
    assert "self_verified" not in _OLD_CAD_MODEL_TEXT


@pytest.mark.parametrize(("trial", "frontier", "remaining"), _FINDINGS_ONLY)
def test_findings_only_gate_pushes_repair_and_self_verification(
    trial: str, frontier: str, remaining: str
) -> None:
    text = _text(frontier, remaining)
    assert f"Remaining: {remaining}." in text, trial
    # No blocker invitation: a Yoetz limit is never a blocker and findings are not obligations.
    assert "yoetz-blocker:<" not in text
    assert "publish decision_recorded" not in text
    assert "A Yoetz limit is never a `yoetz-blocker`" in text
    # Repair first, then self-verify a Yoetz-limit finding, acknowledgement last.
    repair = text.index("repair what you can")
    verify = text.index("respond `self_verified` with how you verified it and the evidence ids")
    acknowledge = text.index("Respond `acknowledged_not_done` only if you truly cannot or will")
    assert repair < verify < acknowledge
    assert "redaction, observation loss or a review-packet limit" in text
    assert "Do not reshape your work for Yoetz" in text
    # The drain note appears only when it changed the decision; it did not here.
    assert "draining" not in text
    assert len(text) <= 2000


@pytest.mark.parametrize(("trial", "frontier", "remaining"), _WITH_OBLIGATIONS)
def test_open_obligations_keep_the_blocker_sentence_but_never_the_confirmation(
    trial: str, frontier: str, remaining: str
) -> None:
    text = _text(frontier, remaining)
    assert f"Remaining: {remaining}." in text, trial
    assert "yoetz-blocker:<authority|consent|credential|dependency_unavailable>" in text
    assert "Data the task says is recoverable is not such a blocker." in text
    assert "Yoetz will ask you about it once." in text
    # How to confirm a blocker is told only after the challenge (the re-check): publishing the
    # line twice up front must never skip it (#985).
    assert "same yoetz-blocker line again" not in text
    assert "same line again" not in text
    assert "A Yoetz limit is never a `yoetz-blocker`" in text
    if "receipt-blocking" in remaining:
        assert "`self_verified`" in text
    assert len(text) <= 2000


def test_drain_note_only_when_it_dropped_a_planned_verification_fact() -> None:
    readiness = SimpleNamespace(
        state="action_required",
        agent_actionable=("obligations_open", "planned_verification_not_observed"),
        open_obligation_count="2",
        receipt_blocking_finding_count="0",
    )
    pending = closure_gate_from_readiness(
        readiness, frontier_sequence="471", frontier_digest=_DIGEST, observation_pending=True
    )
    assert pending is not None
    assert pending.items == ("obligations_open",)
    assert "draining" in pending.text
    settled = closure_gate_from_readiness(
        readiness, frontier_sequence="471", frontier_digest=_DIGEST, observation_pending=False
    )
    assert settled is not None
    assert settled.items == ("obligations_open", "planned_verification_not_observed")
    assert "draining" not in settled.text
    assert "Run each planned verification after your last edit" in settled.text


def test_every_item_and_a_blocker_recheck_fit_the_host_bound() -> None:
    readiness = SimpleNamespace(
        state="action_required",
        agent_actionable=(
            "obligations_open",
            "obligation_blocker_unconfirmed",
            "receipt_findings_unresolved",
            "closing_review_required",
            "planned_verification_failed",
            "planned_verification_not_observed",
            "planned_verification_stale",
            "requested_output_git_ignored",
        ),
        open_obligation_count="18446744073709551615",
        receipt_blocking_finding_count="18446744073709551615",
        blocked_obligations=(
            SimpleNamespace(
                obligation_id="obl_97700000-0000-4000-8000-000000000001",
                blocker_kind="dependency_unavailable",
            ),
        ),
    )
    gate = closure_gate_from_readiness(
        readiness,
        frontier_sequence="18446744073709551615",
        frontier_digest=_DIGEST,
        observation_pending=False,
    )
    assert gate is not None
    # Every host clips at 2,000 characters; the gate must never be clipped.
    assert len(gate.text) <= 2000, len(gate.text)


def test_the_blocker_offer_never_carries_the_confirm_instruction() -> None:
    offer = gate_module._BLOCKER_OFFER_TEXT  # pyright: ignore[reportPrivateUsage]
    assert "again" not in offer
    assert "confirm" not in offer


def _worst_case(*, rows: int, pending: bool, limits: int = 0) -> Any:
    return closure_gate_from_readiness(
        SimpleNamespace(
            state="action_required",
            agent_actionable=(
                "obligations_open",
                "obligation_blocker_unconfirmed",
                "receipt_findings_unresolved",
                "closing_review_required",
                "planned_verification_failed",
                "planned_verification_not_observed",
                "planned_verification_stale",
                "requested_output_git_ignored",
            ),
            open_obligation_count="99",
            receipt_blocking_finding_count="99",
            blocked_obligations=tuple(
                SimpleNamespace(
                    obligation_id=f"obl_97700000-0000-4000-8000-{index:012d}",
                    blocker_kind="dependency_unavailable",
                )
                for index in range(rows)
            ),
            # F3: required limitation ids (at most 64 listed) and an extreme count.
            limitation_refs_required=tuple(
                f"res_97700000-0000-4000-8000-{index:012d}" for index in range(min(limits, 64))
            ),
            limitation_refs_required_count=str(limits),
        ),
        frontier_sequence="999999",
        frontier_digest=_DIGEST,
        observation_pending=pending,
    )


@pytest.mark.parametrize("limits", [0, 1, 9_999])
@pytest.mark.parametrize("pending", [False, True])
@pytest.mark.parametrize("rows", [0, 1, 99])
def test_worst_case_text_stays_within_the_host_bound_and_keeps_the_recheck(
    rows: int, pending: bool, limits: int
) -> None:
    gate = _worst_case(rows=rows, pending=pending, limits=limits)
    assert gate is not None
    assert len(gate.text) <= 2000, len(gate.text)
    if rows:
        assert "Blocker re-check (asked once)" in gate.text
        assert "same yoetz-blocker line again" in gate.text
        if rows > 3:
            assert f"and {rows - 3} more" in gate.text


def test_required_limitation_ids_follow_the_finding_guidance_and_are_bounded() -> None:
    """F3: name at most five ids a completion claim must disclose, then count the rest."""

    readiness = SimpleNamespace(
        state="action_required",
        agent_actionable=("receipt_findings_unresolved",),
        open_obligation_count="0",
        receipt_blocking_finding_count="1",
        blocked_obligations=(),
        limitation_refs_required=tuple(
            f"res_97700000-0000-4000-8000-{index:012d}" for index in range(7)
        ),
        limitation_refs_required_count="70",
    )
    gate = closure_gate_from_readiness(
        readiness,
        frontier_sequence="12",
        frontier_digest=_DIGEST,
        observation_pending=False,
    )
    assert gate is not None
    text = gate.text
    sentence = (
        "Status lists the results a whole-task completion claim must name in limitation_refs: "
    )
    assert sentence in text
    assert text.index("respond `self_verified`") < text.index(sentence) < text.index("Then run")
    assert "res_97700000-0000-4000-8000-000000000004" in text
    assert "res_97700000-0000-4000-8000-000000000005" not in text
    assert "and 65 more (status lists them)" in text
    assert "names only those whose action names a claimed obligation (or none)" in text
    assert "you publish in the same batch as the claim too" in text


@pytest.mark.parametrize("rows", [0, 3])
@pytest.mark.parametrize("acknowledged", [0, 3])
def test_every_stop_gate_token_with_rechecks_never_reports_a_clipped_recheck_as_asked(
    rows: int, acknowledged: int
) -> None:
    """tb4n2 integration: with every lane's Stop-gate token (LB ``declared_output_emptied``, LC
    ``edited_after_last_verification``) a re-check sentence the host bound clips is not reported
    as delivered, so the hook asks it again on the next Stop instead of remembering it."""

    gate = closure_gate_from_readiness(
        SimpleNamespace(
            state="action_required",
            agent_actionable=tuple(gate_module._GATE_TOKENS),  # pyright: ignore[reportPrivateUsage]
            open_obligation_count="18446744073709551615",
            receipt_blocking_finding_count="18446744073709551615",
            blocked_obligations=tuple(
                SimpleNamespace(
                    obligation_id=f"obl_97700000-0000-4000-8000-{index:012d}",
                    blocker_kind="dependency_unavailable",
                )
                for index in range(rows)
            ),
            acknowledged_not_done=tuple(
                f"obl_97700000-0000-4000-8000-{100 + index:012d}" for index in range(acknowledged)
            ),
            acknowledged_obligation_count=str(acknowledged),
            limitation_refs_required=tuple(
                f"res_97700000-0000-4000-8000-{index:012d}" for index in range(64)
            ),
            limitation_refs_required_count="9999",
            standing_limitations=("declared_output_content_moved",),
        ),
        frontier_sequence="18446744073709551615",
        frontier_digest=_DIGEST,
        observation_pending=False,
    )
    assert gate is not None
    assert len(gate.text) <= 2000, len(gate.text)
    ack_keys = tuple(key for key in gate.blocker_keys if key.startswith("ack:"))
    if ack_keys:
        whole = gate_module._acknowledgement_text(ack_keys)  # pyright: ignore[reportPrivateUsage]
        assert whole in gate.text
    blocker_keys = [key for key in gate.blocker_keys if key.endswith(":dependency_unavailable")]
    if blocker_keys:
        assert "same yoetz-blocker line again" in gate.text


def test_the_recheck_only_gate_never_reports_a_clipped_acknowledgement_as_asked() -> None:
    """tb4n2 integration (Codex round 2): ``ready_with_limitations`` with three claimed blocker
    rows, a premise dispute and three acknowledged obligations exceeds the host bound. Only whole
    re-check sentences are kept, and only their keys are reported as asked."""

    readiness = SimpleNamespace(
        state="ready_with_limitations",
        agent_actionable=(),
        blocked_obligations=tuple(
            SimpleNamespace(
                obligation_id=f"obl_97700000-0000-4000-8000-{index:012d}",
                blocker_kind="dependency_unavailable",
            )
            for index in range(3)
        ),
        standing_limitations=("finding_premise_disputed", "declared_output_content_moved"),
        acknowledged_not_done_count="3",
        acknowledged_not_done=tuple(
            f"obl_97700000-0000-4000-8000-{100 + index:012d}" for index in range(3)
        ),
        acknowledged_obligation_count="3",
    )
    gate = closure_gate_from_readiness(
        readiness,
        frontier_sequence="18446744073709551615",
        frontier_digest=_DIGEST,
        observation_pending=False,
    )
    assert gate is not None
    assert len(gate.text) <= 2000, len(gate.text)
    ack_keys = tuple(key for key in gate.blocker_keys if key.startswith("ack:"))
    if ack_keys:
        whole = gate_module._acknowledgement_text(ack_keys)  # pyright: ignore[reportPrivateUsage]
        assert whole in gate.text
    else:
        assert "Acknowledgement re-check" not in gate.text
    if any(key.endswith(":dependency_unavailable") for key in gate.blocker_keys):
        assert "same yoetz-blocker line again" in gate.text
    # The blocker re-check has priority and always fits on its own.
    assert "Blocker re-check (asked once)" in gate.text
