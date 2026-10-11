"""Yoetz's own calls and observations are not "later material"; an observed edit is (tb4n3 RC-6).

Provenance: tb4n3 (28 real Codex runs on 26e9cecf). ``check_current_as_of_earlier_frontier`` (ccaoef)
was added for any later material record. The real post-check suffix is the ``check`` call's own hook
observation plus host stream bookkeeping, so the code bounded 17 of 17 final receipts and was the
sole bound in music D, html D and payments D (B4/B5/C10, issue #1029). Conversely an observed
deliverable edit after the final check kept the check applicable and produced the same standing
code, so a post-check edit looked like a status call (C7).

``test_b4_...`` and ``test_c4_...`` are the repro tests from the verification round
(``verify_n3/scratch_B_consistency/test_family_b.py`` and ``scratch_C_facts/test_family_c_facts.py``),
moved here and strengthened: they assert the agreement on a real replayed ledger with a real check,
not on two lookup tables. The truth table is asserted on every surface that reads the check's
standing; ``tests/integration/application/test_tb4n3_own_calls_cross_surface.py`` adds the public
receipt renderings.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from unit.kernel.test_closure_readiness import (
    _prefix_through_check,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.adapters.memory.ledger import compact_status_coverage
from yoetz.domain.events import (
    ActionKind,
    EventSchema,
    EvidenceKind,
    EvidenceRecordedPayload,
    LedgerRecord,
    ObligationPublishedPayload,
    ResultOutcome,
)
from yoetz.domain.values import evidence_id, obligation_id
from yoetz.kernel.check_standing import check_standing
from yoetz.kernel.closure_readiness import closure_readiness_facts, derive_closure_readiness
from yoetz.kernel.later_material import (
    COMPLETION_SIGNAL_PREFIX,
    OPAQUE_OBSERVATION_PREFIX,
    LaterMaterialClass,
    classify_later_material,
)
from yoetz.kernel.receipt_capacity import receipt_gap_codes
from yoetz.kernel.reducers import invalidates_recorded_check, later_material_class, replay
from yoetz.kernel.task_facts import register_command_identity_key
from yoetz.protocol.coverage import EvidenceImmutability, LedgerFreshness

_CCAOEF = "check_current_as_of_earlier_frontier"
_C = LaterMaterialClass


@pytest.fixture(autouse=True)
def identity_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _evidence(ledger: ObservedLedger, number: int, description: str) -> None:
    from yoetz.domain.values import timestamp_from_string

    ledger.append(
        EventSchema("evidence_recorded", "1.0.0"),
        EvidenceRecordedPayload(
            evidence_id(f"evd_00000000-0000-4000-8000-{number:012d}"),
            EvidenceKind.OTHER,
            EvidenceImmutability.METADATA_ONLY,
            timestamp_from_string("2026-09-29T17:58:11.363Z"),
            description=description,
        ),
        observed=True,
    )


def _own_call(ledger: ObservedLedger, tool: str) -> None:
    ledger.run(
        None, ResultOutcome.SUCCESS, exit_status=0, kind=ActionKind.OTHER, tool=tool, runner="other"
    )


def _bookkeeping(ledger: ObservedLedger, base: int) -> None:
    _evidence(ledger, base, f"{OPAQUE_OBSERVATION_PREFIX}event_msg")
    _evidence(ledger, base + 1, f"{OPAQUE_OBSERVATION_PREFIX}response_item")
    _evidence(ledger, base + 2, f"{COMPLETION_SIGNAL_PREFIX}AgentMessage")


@dataclass(frozen=True)
class _Surfaces:
    """What each reader of the check's standing says about one ledger prefix."""

    superseded: bool
    counted: int
    capacity_codes: frozenset[str]
    compact_gaps: frozenset[str]
    freshness: LedgerFreshness
    readiness_applicability: str
    readiness_bounds: bool
    readiness_actionable: tuple[str, ...]
    readiness_standing: tuple[str, ...]


def _surfaces(records: tuple[LedgerRecord, ...]) -> _Surfaces:
    projection = replay(records)
    standing = check_standing(projection, records)
    facts = closure_readiness_facts(projection, records)
    coverage = compact_status_coverage(records, projection)
    # The markers a compact status row would carry: the folded check coverage's gaps.
    split = derive_closure_readiness(
        ("coverage_gaps_declared",) if coverage.known_gaps else (),
        coverage.known_gaps,
        facts,
        semantic_review_required=False,
    )
    return _Surfaces(
        superseded=standing.superseded,
        counted=len(standing.counted),
        capacity_codes=frozenset(receipt_gap_codes(projection, records)),
        compact_gaps=frozenset(coverage.known_gaps),
        freshness=projection.freshness,
        readiness_applicability=facts.check_applicability,
        readiness_bounds=facts.earlier_frontier_bounds,
        readiness_actionable=split.agent_actionable,
        readiness_standing=split.standing_limitations,
    )


def _after_check() -> ObservedLedger:
    return ObservedLedger(records=list(_prefix_through_check()))


# --- B4 / B5 / C10 -------------------------------------------------------------------------------


def test_b4_earlier_frontier_gap_class_agrees_with_receipt_bound() -> None:
    """Repro: readiness classed ccaoef "standing" (nothing to do) while the receipt treated it as
    bounding unless the suffix was responses only, and the suffix was never responses only.

    After the fix the gap exists only for a suffix Yoetz cannot prove harmless; the same suffix is
    what the receipt counts as bounding, and readiness then lists the code as work (one more
    check removes it). A suffix of Yoetz's own calls and host bookkeeping adds no gap anywhere.
    """

    # The real post-check shape: the check call's own observation, status/receipt polls, and host
    # stream bookkeeping. Nothing here can have changed the work the check read.
    own = _after_check()
    for tool in ("mcp__yoetz__check", "mcp__yoetz__status", "mcp__yoetz__receipt"):
        _own_call(own, tool)
    _bookkeeping(own, 9100)
    quiet = _surfaces(own.prefix)
    assert quiet.superseded is False and quiet.counted == 0
    assert _CCAOEF not in quiet.capacity_codes
    assert _CCAOEF not in quiet.compact_gaps
    assert quiet.readiness_applicability == "applicable"
    assert quiet.readiness_bounds is False
    assert _CCAOEF not in quiet.readiness_actionable + quiet.readiness_standing
    assert quiet.freshness is not LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE

    # A command Yoetz cannot classify may have changed the work: the disclosure stays, the receipt
    # side counts it, and readiness no longer says "nothing further to do" beside it.
    script = _after_check()
    _own_call(script, "mcp__yoetz__check")
    script.passes("python gen.py")
    bounded = _surfaces(script.prefix)
    assert bounded.superseded is False and bounded.counted >= 1
    assert _CCAOEF in bounded.capacity_codes
    assert _CCAOEF in bounded.compact_gaps
    assert bounded.readiness_bounds is True
    assert _CCAOEF in bounded.readiness_actionable
    assert _CCAOEF not in bounded.readiness_standing
    assert bounded.freshness is not LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE

    # The three surfaces cannot disagree on any variant: the code is in the receipt-capacity fold,
    # the compact coverage and the readiness work list together, or in none of them.
    for state in (quiet, bounded):
        in_capacity = _CCAOEF in state.capacity_codes
        assert in_capacity == (_CCAOEF in state.compact_gaps)
        assert in_capacity == (state.counted > 0)
        assert state.readiness_bounds == (_CCAOEF in state.readiness_actionable)


def test_c4_observed_edit_after_check_supersedes_it() -> None:
    """Repro (C7): a hook-observed deliverable/workspace edit after the check never invalidated it,
    so readiness kept the check applicable and the closing review current; the receipt only added
    the standing code a later `status` call also produces."""

    ledger = _after_check()
    check = ledger.prefix[-1]
    ledger.edit()
    edit_action, edit_result = ledger.prefix[-2], ledger.prefix[-1]
    projection = replay(ledger.prefix)
    for record in (edit_action, edit_result):
        assert invalidates_recorded_check(
            record,
            check.ledger.ingestion_sequence,
            (),
            limitation_finding_ids=frozenset(),
            projection=projection,
        ), "an observed edit after the check must make it not_applicable"
        assert later_material_class(record, projection) is _C.EDIT_OR_WRITE

    state = _surfaces(ledger.prefix)
    assert state.superseded is True
    assert "check_not_applicable" in state.capacity_codes
    assert _CCAOEF not in state.capacity_codes
    assert state.readiness_applicability == "not_applicable"
    assert "check_not_applicable" in state.readiness_actionable
    # The projection's freshness follows the same rule (the reducer, not only the readers).
    assert state.freshness is LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE
    facts = closure_readiness_facts(projection, ledger.prefix)
    assert facts.closing_review_current is False, "the closing review is required again"
    cause = facts.check_cause
    assert cause is not None
    assert (cause.effect, cause.record.material.material_class) == ("superseded", _C.EDIT_OR_WRITE)
    assert cause.record.event_id == edit_action.event_id
    assert cause.check_event_id == check.event_id


@pytest.mark.parametrize("outcome", (ResultOutcome.FAILURE, ResultOutcome.UNKNOWN))
def test_c4_a_failed_or_outcomeless_edit_still_supersedes(outcome: ResultOutcome) -> None:
    """The safe direction: Yoetz cannot tell that a failed patch left the files unchanged."""

    ledger = _after_check()
    ledger.edit(outcome)
    assert _surfaces(ledger.prefix).superseded is True


@pytest.mark.parametrize(
    ("scope", "expected"),
    (
        ("yoetz_owned", _C.NON_COUNTING_WRITE),
        ("scratch", _C.NON_COUNTING_WRITE),
        ("outside_workspace", _C.EDIT_OR_WRITE),
        (None, _C.EDIT_OR_WRITE),
    ),
)
def test_write_scope_decides_whether_an_edit_counts(scope: str | None, expected: _C) -> None:
    ledger = _after_check()
    ledger.edit(write_scope=scope)
    projection = replay(ledger.prefix)
    assert {
        classify_later_material(record, projection).material_class for record in ledger.prefix[-2:]
    } == {expected}
    assert _surfaces(ledger.prefix).superseded is (expected is _C.EDIT_OR_WRITE)


def test_a_declared_temp_output_makes_a_scratch_write_a_deliverable_edit() -> None:
    """ADR-042 precedence: a deliverable declared under /tmp is not scratch."""

    from yoetz.domain.events import (
        ObligationStatus,
        PlanPublishedPayload,
        RequestedItem,
        RequestedItemKind,
        RequestedItemRole,
    )

    obligation = obligation_id("obl_00000000-0000-4000-8000-0000000000b4")
    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", "1.1.0"),
        ObligationPublishedPayload(
            obligation_id=obligation,
            description="Deliver",
            evidence_expectation="files",
            status=ObligationStatus.OPEN,
            requested_items=(
                RequestedItem(
                    RequestedItemKind.FILE, "/tmp/result.json", role=RequestedItemRole.OUTPUT
                ),
            ),
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (obligation,)),
        observed=False,
    )
    ledger.edit(write_scope="scratch")
    ledger.edit(write_scope="yoetz_owned")
    projection = replay(ledger.prefix)
    scratch, receipt = ledger.prefix[-4], ledger.prefix[-2]
    assert classify_later_material(scratch, projection).material_class is _C.EDIT_OR_WRITE
    # A Yoetz receipt is the output about the check: it never counts, declared or not.
    assert classify_later_material(receipt, projection).material_class is _C.NON_COUNTING_WRITE


@pytest.mark.parametrize(
    ("tool", "runner", "expected"),
    (
        ("exec_command", "exploration", _C.EXPLORATION),
        ("Read", "exploration", _C.EXPLORATION),
        ("exec_command", "test", _C.OTHER),
        ("exec_command", "build", _C.OTHER),
        ("exec_command", "vcs", _C.OTHER),
        ("exec_command", "compound", _C.OTHER),
        ("exec_command", "other", _C.OTHER),
    ),
)
def test_only_the_closed_exploration_runner_class_is_read_only(
    tool: str, runner: str, expected: _C
) -> None:
    ledger = _after_check()
    ledger.run(
        None,
        ResultOutcome.SUCCESS,
        exit_status=0,
        kind=ActionKind.COMMAND,
        tool=tool,
        runner=runner,
    )
    projection = replay(ledger.prefix)
    assert {
        classify_later_material(record, projection).material_class for record in ledger.prefix[-2:]
    } == {expected}
