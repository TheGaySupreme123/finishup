"""FinishUP's own calls and observations are not "later material"; an observed edit is (tb4n3 RC-6).

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
from finishup.adapters.memory.ledger import compact_status_coverage
from finishup.domain.events import (
    ActionKind,
    EventSchema,
    EvidenceKind,
    EvidenceRecordedPayload,
    LedgerRecord,
    ObligationPublishedPayload,
    ResultOutcome,
)
from finishup.domain.values import evidence_id, obligation_id
from finishup.kernel.check_standing import check_standing
from finishup.kernel.closure_readiness import closure_readiness_facts, derive_closure_readiness
from finishup.kernel.later_material import (
    COMPLETION_SIGNAL_PREFIX,
    OPAQUE_OBSERVATION_PREFIX,
    LaterMaterialClass,
    classify_later_material,
)
from finishup.kernel.receipt_capacity import receipt_gap_codes
from finishup.kernel.reducers import invalidates_recorded_check, later_material_class, replay
from finishup.kernel.task_facts import register_command_identity_key
from finishup.protocol.coverage import EvidenceImmutability, LedgerFreshness
from unit.kernel.test_closure_readiness import (
    _prefix_through_check,  # pyright: ignore[reportPrivateUsage]
)

_CCAOEF = "check_current_as_of_earlier_frontier"
_C = LaterMaterialClass


@pytest.fixture(autouse=True)
def identity_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _evidence(ledger: ObservedLedger, number: int, description: str) -> None:
    from finishup.domain.values import timestamp_from_string

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
        readiness_actionable=split.agent_actionable,
        readiness_standing=split.standing_limitations,
    )


def _after_check() -> ObservedLedger:
    return ObservedLedger(records=list(_prefix_through_check()))


# --- B4 / B5 / C10 -------------------------------------------------------------------------------


def test_b4_earlier_frontier_gap_class_agrees_with_receipt_bound() -> None:
    """Repro: readiness classed ccaoef "standing" (nothing to do) while the receipt treated it as
    bounding unless the suffix was responses only, and the suffix was never responses only.

    After the fix the gap exists only for a suffix FinishUP cannot prove harmless, and every surface
    agrees on that: capacity fold, compact coverage, readiness standing list and the receipt count
    the same records. A suffix of FinishUP's own calls and host bookkeeping adds no gap anywhere.
    """

    # The real post-check shape: the check call's own observation, status/receipt polls, and host
    # stream bookkeeping. Nothing here can have changed the work the check read.
    own = _after_check()
    for tool in ("mcp__finishup__check", "mcp__finishup__status", "mcp__finishup__receipt"):
        _own_call(own, tool)
    _bookkeeping(own, 9100)
    quiet = _surfaces(own.prefix)
    assert quiet.superseded is False and quiet.counted == 0
    assert _CCAOEF not in quiet.capacity_codes
    assert _CCAOEF not in quiet.compact_gaps
    assert quiet.readiness_applicability == "applicable"
    assert _CCAOEF not in quiet.readiness_actionable + quiet.readiness_standing
    assert quiet.freshness is not LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE

    # A command FinishUP cannot classify may have changed the work: the disclosure stays and the
    # receipt side counts it. Readiness keeps the code a standing limitation: it is not agent work,
    # because any instruction derived from it can regenerate after the check it asks for (the
    # FinishUP CLI run through a shell, Cursor's tool-identity-free post-only results, ADR-040
    # section 7), and "nothing to do" is true of it (Codex review 1 and 2).
    script = _after_check()
    _own_call(script, "mcp__finishup__check")
    script.passes("python gen.py")
    bounded = _surfaces(script.prefix)
    assert bounded.superseded is False and bounded.counted >= 1
    assert _CCAOEF in bounded.capacity_codes
    assert _CCAOEF in bounded.compact_gaps
    assert _CCAOEF not in bounded.readiness_actionable
    assert _CCAOEF in bounded.readiness_standing
    assert bounded.freshness is not LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE
    facts = closure_readiness_facts(replay(script.prefix), script.prefix)
    assert facts.check_cause is not None and facts.check_cause.effect == "bounds_conclusion"
    assert facts.check_cause.record.material.rule == "unclassified_observed_action"

    # A host result that names no tool bounds the receipt the same way and is likewise standing.
    blind = _after_check()
    _evidence(blind, 9300, "Observed post-only tool result")
    anonymous = _surfaces(blind.prefix)
    assert anonymous.counted == 1
    assert _CCAOEF in anonymous.capacity_codes and _CCAOEF in anonymous.compact_gaps
    assert _CCAOEF not in anonymous.readiness_actionable
    assert _CCAOEF in anonymous.readiness_standing

    # The surfaces cannot disagree on any variant: the code is in the receipt-capacity fold, the
    # compact coverage and the readiness standing list together, or in none of them.
    for state in (quiet, bounded, anonymous):
        in_capacity = _CCAOEF in state.capacity_codes
        assert in_capacity == (_CCAOEF in state.compact_gaps)
        assert in_capacity == (_CCAOEF in state.readiness_standing)
        assert in_capacity == (state.counted > 0)


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
    """The safe direction: FinishUP cannot tell that a failed patch left the files unchanged."""

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

    from finishup.domain.events import (
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
    # A FinishUP receipt is the output about the check: it never counts, declared or not.
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


def test_a_receipt_saved_into_a_declared_output_directory_never_supersedes() -> None:
    """lake D (tb4n2): the agent saved finishup_receipt.json into the declared output directory after
    its last check. ``task_facts.non_counting_edits_exempt`` counts that write for verification
    staleness (a directory output makes it part of the delivery), but a check can never cover the
    receipt that reports on it: counting it would invalidate the check that produced it, and the
    next saved receipt would do it again."""

    from finishup.domain.events import (
        ObligationStatus,
        PlanPublishedPayload,
        RequestedItem,
        RequestedItemKind,
        RequestedItemRole,
    )
    from finishup.kernel.task_facts import non_counting_edits_exempt

    obligation = obligation_id("obl_00000000-0000-4000-8000-0000000000b5")
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
                    RequestedItemKind.DIRECTORY, "/app/output", role=RequestedItemRole.OUTPUT
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
    ledger.edit(write_scope="yoetz_owned")
    projection = replay(ledger.prefix)
    # The verification-staleness rule counts it (ADR-042 decision 1) ...
    assert "write yoetz_owned" not in non_counting_edits_exempt(projection)
    # ... the check-supersession rule never does.
    assert {
        classify_later_material(record, projection).material_class for record in ledger.prefix[-2:]
    } == {_C.NON_COUNTING_WRITE}


def test_captured_content_takes_the_class_of_the_call_it_was_recorded_under() -> None:
    """Codex review 1: saving finishup_receipt.md with captured patch content records an evidence row
    under the action. That row is the call's output, not a second, unclassified observation: it
    must not turn an ignored write into a counted record (and then a recheck loop)."""

    ledger = _after_check()
    check_sequence = ledger.prefix[-1].ledger.ingestion_sequence
    ledger.edit(write_scope="yoetz_owned")
    action = ledger.prefix[-2]
    from finishup.domain.values import timestamp_from_string

    ledger.append(
        EventSchema("evidence_recorded", "1.0.0"),
        EvidenceRecordedPayload(
            evidence_id("evd_00000000-0000-4000-8000-000000009401"),
            EvidenceKind.OTHER,
            EvidenceImmutability.METADATA_ONLY,
            timestamp_from_string("2026-09-29T17:58:11.363Z"),
            description="Observation-captured workspace_diff",
        ),
        observed=True,
        causal_parents=(action.event_id,),
    )
    standing = check_standing(replay(ledger.prefix), ledger.prefix)
    assert check_sequence < ledger.prefix[-1].ledger.ingestion_sequence
    assert standing.superseded is False
    assert standing.counted == ()
    assert standing.ignored[_C.NON_COUNTING_WRITE] == 3  # the action, its result, its evidence
    # An unknown description without that lineage stays disclosed.
    orphan = _after_check()
    _evidence(orphan, 9402, "Observation-captured workspace_diff")
    assert len(check_standing(replay(orphan.prefix), orphan.prefix).counted) == 1


def test_a_declared_finishup_tree_deliverable_keeps_counting() -> None:
    """Codex review 1: the receipt exemption is for the receipt, not for a task whose product is
    the packaged plugin or skill (a declared output under .agents/skills/finishup)."""

    from finishup.domain.events import (
        ObligationStatus,
        PlanPublishedPayload,
        RequestedItem,
        RequestedItemKind,
        RequestedItemRole,
    )

    obligation = obligation_id("obl_00000000-0000-4000-8000-0000000000b6")
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
                    RequestedItemKind.FILE,
                    "/app/.agents/skills/finishup/SKILL.md",
                    role=RequestedItemRole.OUTPUT,
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
    ledger.edit(write_scope="yoetz_owned")
    projection = replay(ledger.prefix)
    assert {
        classify_later_material(record, projection).material_class for record in ledger.prefix[-2:]
    } == {_C.EDIT_OR_WRITE}


def test_a_find_that_writes_a_file_is_not_exploration() -> None:
    """Codex review 1: ``find -fprint0 FILE`` writes FILE; the read-only runner class must not
    admit it, because the later-material rule now ignores exploration entirely."""

    from finishup.domain.observation_selection import command_runner_class

    for command in (
        "find . -fprint0 manifest.bin",
        "find . -fprint list.txt",
        "find . -okdir rm {} +",
        "find . -delete",
    ):
        assert command_runner_class({"command": command}) != "exploration", command
    assert command_runner_class({"command": "find . -name '*.py'"}) == "exploration"


def test_a_wrapped_read_is_not_proven_read_only() -> None:
    """Codex review 2: ``uv run --upgrade cat README.md`` rewrites uv.lock before it reads."""

    from finishup.domain.observation_selection import command_runner_class

    for command in ("uv run --upgrade cat README.md", "uv run cat README.md", "poetry run ls"):
        assert command_runner_class({"command": command}) != "exploration", command
    assert command_runner_class({"command": "cat README.md"}) == "exploration"


def test_a_late_output_of_an_edit_is_disclosed_but_never_a_second_supersession() -> None:
    """Codex review 2: the walk and the reducer must agree on what supersedes. Evidence recorded
    under an edit action that arrived before the check is the edit's late output: counted (the
    disclosure stays), never superseding, and the same in the reducer, which cannot see lineage."""

    from finishup.domain.values import timestamp_from_string

    ledger = ObservedLedger()
    ledger.edit()
    action = ledger.prefix[-2]
    check_like_boundary = ledger.prefix[-1].ledger.ingestion_sequence
    ledger.append(
        EventSchema("evidence_recorded", "1.0.0"),
        EvidenceRecordedPayload(
            evidence_id("evd_00000000-0000-4000-8000-000000009501"),
            EvidenceKind.OTHER,
            EvidenceImmutability.METADATA_ONLY,
            timestamp_from_string("2026-09-29T17:58:11.363Z"),
            description="Observation-captured workspace_diff",
        ),
        observed=True,
        causal_parents=(action.event_id,),
    )
    projection = replay(ledger.prefix)
    evidence = ledger.prefix[-1]
    assert evidence.ledger.ingestion_sequence > check_like_boundary
    material = classify_later_material(evidence, projection)
    assert (material.material_class, material.rule) == (_C.OTHER, "evidence_of_edit") or (
        # Without the lineage map (the reducer's view) it is plain unclassified evidence.
        material.material_class is _C.OTHER
    )
    assert not material.supersedes
    with_lineage = classify_later_material(
        evidence,
        projection,
        actions_by_event={action.event_id: action.payload},  # type: ignore[dict-item]
    )
    assert (with_lineage.material_class, with_lineage.rule) == (_C.OTHER, "evidence_of_edit")
    assert not with_lineage.supersedes


def test_only_the_packaged_finishup_trees_end_the_receipt_exemption() -> None:
    """Codex review 2: ``.agents/skills/project-skill`` is the project's, not FinishUP's."""

    from finishup.domain.write_scope import finishup_tree_overlap

    for overlapping in (
        "/app/.agents/skills/finishup/SKILL.md",
        "/app/.agents/plugins/finishup",
        "/app/.agents",
        "/app/.agents/skills",
        "/app/.agents/plugins/",
    ):
        assert finishup_tree_overlap(overlapping), overlapping
    for separate in (
        "/app/.agents/skills/project-skill",
        "/app/.agents/skills/project-skill/SKILL.md",
        "/app/output",
        "/app",
        "",
    ):
        assert not finishup_tree_overlap(separate), separate
