"""The composition names a task input outside the workspace the owner did not admit (issue #1102).

RC6f: outside-input roots were configured in none of the pilot's trials, so a task file outside
the workspace never reached the reviewer and nothing said so. The composition now records the
closed coverage code ``task_input_outside_not_admitted`` from the frozen case alone, and the
``semantic_case_built`` record counts the task inputs. Neither carries a path.
"""

from __future__ import annotations

from dataclasses import replace

from finishup.application.check import SEMANTIC_EVALUATION_GAPS
from finishup.application.check_change import CheckChangeOutcome
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.receipts import (
    CHECK_TIME_CHANGE_GAPS,
    TASK_INPUT_OUTSIDE_NOT_ADMITTED_GAP,
    check_time_change_gap_sentence,
)
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.ports.change_capture import TaskInputFile
from finishup.service import ready_composition
from unit.application.test_semantic_case_packet_completeness import (
    _build,  # pyright: ignore[reportPrivateUsage]
    _change,  # pyright: ignore[reportPrivateUsage]
    _statement_case,  # pyright: ignore[reportPrivateUsage]
)

_review_inputs = ready_composition._review_inputs  # pyright: ignore[reportPrivateUsage]
_outside_not_admitted = ready_composition._outside_not_admitted  # pyright: ignore[reportPrivateUsage]
_task_input_counts = ready_composition._task_input_counts  # pyright: ignore[reportPrivateUsage]

_EXPANDED = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
_OUTSIDE = "/shared/legacy app/main.c"


def _case(statement: str) -> DeterministicCase:
    case = _statement_case()
    assert case.task_statement is not None
    return replace(case, task_statement=replace(case.task_statement, text=statement))


def test_the_code_comes_from_the_frozen_check_change_decision_alone() -> None:
    """The read decided against its own root and froze one flag; the composition only reads it,
    so the session's optional workspace label never decides (review r1-8)."""

    case = _case(f'Port the legacy app "{_OUTSIDE}" to Python as /app/main.py.')
    inputs = _review_inputs(case, _EXPANDED)
    assert inputs[0][:2] == (_OUTSIDE, "/app/main.py")
    structural = ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL)
    assert _review_inputs(case, structural) == ((), frozenset())

    flagged = _change()
    flagged = replace(flagged, capture=replace(flagged.capture, outside_inputs_not_admitted=True))
    assert _outside_not_admitted(CheckChangeOutcome(change=flagged))
    assert not _outside_not_admitted(CheckChangeOutcome(change=_change()))
    assert not _outside_not_admitted(CheckChangeOutcome())
    assert not _outside_not_admitted(CheckChangeOutcome(unavailable=True, reason="not_git"))

    # The code rides the packet and the check's evaluation vocabulary, beside the change's own
    # codes but not one of them, and the reviewer and every surface read one fixed sentence.
    assert TASK_INPUT_OUTSIDE_NOT_ADMITTED_GAP in SEMANTIC_EVALUATION_GAPS
    assert TASK_INPUT_OUTSIDE_NOT_ADMITTED_GAP not in CHECK_TIME_CHANGE_GAPS
    semantic = _build(case, gaps=(TASK_INPUT_OUTSIDE_NOT_ADMITTED_GAP,))
    assert TASK_INPUT_OUTSIDE_NOT_ADMITTED_GAP in semantic.packet.coverage.known_gaps
    sentence = check_time_change_gap_sentence(TASK_INPUT_OUTSIDE_NOT_ADMITTED_GAP)
    assert sentence is not None and "legacy" not in sentence and "/shared" not in sentence


def test_the_task_input_counters_are_counts_only() -> None:
    case = _case(f'Port "{_OUTSIDE}" following DESIGN.md and the code in src/dedup/.')
    inputs = _review_inputs(case, _EXPANDED)
    listing = b"FinishUP listing of src/dedup/: 1 files\nsrc/dedup/config.py\n"
    member = b"THRESHOLD = 1\n"
    change = _change(
        inputs=(
            TaskInputFile("src/dedup/", listing, len(listing), summary=True),
            TaskInputFile("src/dedup/config.py", member, len(member), origin="task_directory"),
        )
    )
    semantic = _build(case, change=change)

    counts = _task_input_counts(inputs, CheckChangeOutcome(change=change), semantic, True)

    assert counts == {
        "semantic_task_input_candidates": len(inputs[0]),
        "semantic_task_inputs_read": 2,
        "semantic_task_input_listings": 1,
        "semantic_task_input_excerpts_selected": 2,
        "semantic_task_inputs_outside_not_admitted": 1,
    }
    assert all(type(value) is int for value in counts.values())
    empty = _task_input_counts(((), frozenset()), CheckChangeOutcome(), _build(case), False)
    assert set(empty.values()) == {0}
