"""#1118 V5: a repaired AI-powered finding is not held open by a stale task fact forever.

Bun (tb4h-smoke10c): the last completed review listed ``planned_verification_failed`` and could
not assess the repaired finding; every later check skipped the review for that reason, so the
eligibility of ``respond self_verified`` stayed frozen on that review's task facts. The agent
cleared the failed verification, but each ``self_verified`` was refused with the stale code and
the closure loop ran for 51 more FinishUP calls. Task facts are recomputed by every check, so a
newer check that ran the finding's policy without a review now supplies them; the reviewer-side
reasons still come from the last completed review, and a fact the newer check still lists keeps
refusing.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import cast

import pytest

from builders.policy_cases import evt, finding_record, fnd, obl
from finishup.domain.events import CheckRecordedPayload, LedgerRecord
from finishup.domain.findings import FindingOrigin
from finishup.kernel import finding_resolution, task_fact_scope
from finishup.kernel.projections import ProjectionState, empty_projection_state
from finishup.kernel.self_verification import (
    FINDING_NOT_PROOF_LIMITED,
    self_verification_blocking_reasons,
    self_verification_refusal,
)
from finishup.kernel.task_facts import TaskFactSignals
from unit.kernel import test_finding_resolution as fr

_FAILED = "planned_verification_failed"
_SKIPPED = "semantic_review_skipped_insufficient_packet"


@pytest.fixture(autouse=True)
def facts_about_the_findings_obligation(monkeypatch: pytest.MonkeyPatch) -> None:
    """The planned-verification facts name the obligation the finding is about, so they bear."""

    markers = tuple((code, obl(1)) for code in (_FAILED, "planned_verification_not_observed"))
    signals = TaskFactSignals(codes=(), markers=markers, acting_started=True)
    monkeypatch.setattr(task_fact_scope, "task_fact_signals", lambda *_a: signals)  # pyright: ignore[reportUnknownLambdaType,reportUnknownArgumentType]
    # The repair: an edit recorded after the finding, before each check (``_changed_state``).
    monkeypatch.setattr(
        finding_resolution,
        "_historical_proof_state",
        lambda check, *_a: fr._changed_state(check),  # pyright: ignore[reportPrivateUsage,reportUnknownLambdaType,reportUnknownArgumentType]
    )


def _row(sequence: int, check: CheckRecordedPayload) -> object:
    return SimpleNamespace(
        event_id=evt(sequence),
        schema=SimpleNamespace(name="check_recorded"),
        ledger=SimpleNamespace(ingestion_sequence=sequence),
        payload=check,
    )


def _state() -> ProjectionState:
    finding = fr._finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)  # pyright: ignore[reportPrivateUsage]
    return replace(
        empty_projection_state(),
        frontier=20,
        head_digest=fr._DIGEST,  # pyright: ignore[reportPrivateUsage]
        findings={finding.finding_id: finding_record(finding, 4)},
    )


def _review(*gaps: str) -> CheckRecordedPayload:
    """The last completed review: it could not assess the repaired finding."""

    check = fr._review_check(*gaps, "semantic_reference_scope_reduced")  # pyright: ignore[reportPrivateUsage]
    return replace(check, semantic_conclusion="insufficient_packet")


def _skipped(*gaps: str) -> CheckRecordedPayload:
    """A later local check: the policy ran, the review was skipped (a FinishUP limit)."""

    coverage = fr._coverage(gaps=("semantic_review_not_requested", _SKIPPED, *gaps))  # pyright: ignore[reportPrivateUsage]
    return fr._check(tested=12, coverage=coverage)  # pyright: ignore[reportPrivateUsage]


def _records(*rows: object) -> tuple[LedgerRecord, ...]:
    return cast(tuple[LedgerRecord, ...], rows)


def test_a_cleared_task_fact_no_longer_refuses_self_verification() -> None:
    state = _state()
    stale = _records(_row(8, _review(_FAILED)))
    # With only the review, its own failed verification is agent work: refused.
    assert self_verification_refusal(state, fnd(1), stale) == FINDING_NOT_PROOF_LIMITED
    assert self_verification_blocking_reasons(state, fnd(1), stale) == ("coverage:" + _FAILED,)
    # The agent re-ran it; a later check no longer lists it, though the review was skipped.
    cleared = _records(_row(8, _review(_FAILED)), _row(12, _skipped()))
    assert self_verification_blocking_reasons(state, fnd(1), cleared) == ()
    assert self_verification_refusal(state, fnd(1), cleared) is None


def test_a_task_fact_the_newer_check_still_lists_keeps_refusing() -> None:
    state = _state()
    still = _records(_row(8, _review(_FAILED)), _row(12, _skipped(_FAILED)))
    assert self_verification_blocking_reasons(state, fnd(1), still) == ("coverage:" + _FAILED,)
    # A fact only the newer check sees is current work as well.
    fresh = _records(_row(8, _review()), _row(12, _skipped("planned_verification_not_observed")))
    assert self_verification_blocking_reasons(state, fnd(1), fresh) == (
        "coverage:planned_verification_not_observed",
    )


def test_a_skipped_review_alone_never_makes_a_finding_eligible() -> None:
    """The review-side reasons still come from the last completed review: nothing is relaxed."""

    state = _state()
    full = fr._review_check()  # pyright: ignore[reportPrivateUsage]
    seen = replace(full, semantic_conclusion="challenges_returned", returned_finding_ids=(fnd(1),))
    records = _records(_row(8, seen), _row(12, _skipped()))
    assert self_verification_refusal(state, fnd(1), records) == FINDING_NOT_PROOF_LIMITED
